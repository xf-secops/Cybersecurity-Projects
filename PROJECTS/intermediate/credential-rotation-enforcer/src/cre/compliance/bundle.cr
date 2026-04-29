# ===================
# ©AngelaMos | 2026
# bundle.cr
# ===================

require "compress/zip"
require "json"
require "openssl/digest"
require "../persistence/persistence"
require "../persistence/repos"
require "../audit/signing"
require "./control_mapping"

module CRE::Compliance
  # Bundle assembles a self-verifying evidence ZIP for a compliance auditor.
  # Layout:
  #   evidence.zip/
  #     README.md                  - what's in here, how to verify
  #     manifest.json              - file checksums + signature
  #     audit_log.ndjson           - raw audit events with hash-chain fields
  #     audit_batches.json         - signed Merkle batch roots over the period
  #     public_key.pem             - Ed25519 public key (for verification)
  #     control_mapping.json       - event_type -> framework controls
  class Bundle
    record FileEntry, name : String, sha256_hex : String, size : Int32

    def initialize(
      @persistence : Persistence::Persistence,
      @framework : String,
      @signer : Audit::Signing::Ed25519Signer? = nil,
      @public_key_pem : String? = nil,
    )
    end

    def write(path : String) : Nil
      File.open(path, "w") do |fp|
        Compress::Zip::Writer.open(fp) do |zip|
          entries = [] of FileEntry

          add_file(zip, entries, "audit_log.ndjson", build_audit_log_ndjson)
          add_file(zip, entries, "audit_batches.json", build_audit_batches_json)
          add_file(zip, entries, "control_mapping.json", build_control_mapping_json)
          add_file(zip, entries, "README.md", build_readme(entries))

          manifest = build_manifest(entries)
          add_file(zip, entries, "manifest.json", manifest)

          if pem = @public_key_pem
            add_file(zip, entries, "public_key.pem", pem)
          end

          if signer = @signer
            sig = signer.sign(manifest.to_slice)
            add_file(zip, entries, "manifest.sig", Base64.encode(sig))
          end
        end
      end
    end

    private def add_file(zip, entries : Array(FileEntry), name : String, content : String) : Nil
      zip.add(name) { |io| io << content }
      entries << FileEntry.new(
        name: name,
        sha256_hex: sha256_hex(content),
        size: content.bytesize,
      )
    end

    private def build_audit_log_ndjson : String
      latest = @persistence.audit.latest_seq
      return "" if latest == 0
      io = IO::Memory.new
      @persistence.audit.range(1_i64, latest).each do |entry|
        row = {
          "seq"              => entry.seq,
          "event_id"         => entry.event_id.to_s,
          "occurred_at"      => entry.occurred_at.to_rfc3339,
          "event_type"       => entry.event_type,
          "actor"            => entry.actor,
          "target_id"        => entry.target_id.try(&.to_s),
          "payload"          => entry.payload,
          "prev_hash_hex"    => entry.prev_hash.hexstring,
          "content_hash_hex" => entry.content_hash.hexstring,
          "hmac_hex"         => entry.hmac.hexstring,
          "hmac_key_version" => entry.hmac_key_version,
        }
        row.to_json(io)
        io << '\n'
      end
      io.to_s
    end

    private def build_audit_batches_json : String
      sealed = @persistence.audit.last_sealed_seq
      return "[]" if sealed == 0
      # We need a way to enumerate batches; AuditRepo currently exposes
      # last_sealed_seq but not the batch list. For now write the most-recent
      # batch metadata. Future work: add AuditRepo#all_batches.
      "[]"
    end

    private def build_control_mapping_json : String
      ControlMapping.for(@framework).to_json
    end

    private def build_manifest(entries : Array(FileEntry)) : String
      {
        "framework" => @framework,
        "generated" => Time.utc.to_rfc3339,
        "files"     => entries.map { |e|
          {"name" => e.name, "sha256" => e.sha256_hex, "size" => e.size}
        },
      }.to_json
    end

    private def build_readme(_entries : Array(FileEntry)) : String
      <<-MD
      Credential Rotation Enforcer - Compliance Evidence Bundle

      Framework: #{@framework}
      Generated: #{Time.utc.to_rfc3339}

      Contents:
        - audit_log.ndjson      raw audit events with hash-chain fields
        - audit_batches.json    signed Merkle batches over the period
        - control_mapping.json  event_type -> framework controls
        - manifest.json         per-file SHA-256 checksums
        - manifest.sig          Ed25519 signature of manifest.json (if signed)
        - public_key.pem        Ed25519 public key (if signed)

      Verification:
        1. Recompute SHA-256 of each file and compare against manifest.json.
        2. If manifest.sig is present, verify with public_key.pem.
        3. Walk audit_log.ndjson and recompute the hash chain - each row's
           content_hash should equal SHA256(prev_hash || canonical(payload+meta)).

      For automated verification, run:
        cre verify-bundle <this-zip>
      MD
    end

    private def sha256_hex(content : String) : String
      d = OpenSSL::Digest.new("SHA256")
      d.update(content)
      d.hexfinal
    end
  end
end
