# ===================
# ©AngelaMos | 2026
# env_file.cr
# ===================

require "../crypto/random"
require "./rotator"

module CRE::Rotators
  # EnvFileRotator manages credentials stored as KEY=value lines in a .env file.
  # The rotation produces fresh random bytes (base64-encoded) and atomically
  # swaps the live file on commit using temp+rename.
  #
  # Credential.tags must include:
  #   "path" - absolute path to the .env file
  #   "key"  - the key whose value rotates
  class EnvFileRotator < Rotator
    register_as :env_file

    DEFAULT_BYTES = 32

    def kind : Symbol
      :env_file
    end

    def can_rotate?(c : Domain::Credential) : Bool
      c.kind.env_file? && !c.tag("path").nil? && !c.tag("key").nil?
    end

    def generate(c : Domain::Credential) : Domain::NewSecret
      raise RotatorError.new("missing 'path' or 'key' tag") unless can_rotate?(c)
      bytes = (c.tag("bytes") || DEFAULT_BYTES.to_s).to_i
      raw = CRE::Crypto::Random.bytes(bytes)
      encoded = Base64.urlsafe_encode(raw, padding: false)
      Domain::NewSecret.new(
        ciphertext: encoded.to_slice,
        metadata: {"key" => c.tag("key").not_nil!},
      )
    end

    def apply(c : Domain::Credential, s : Domain::NewSecret) : Nil
      path = c.tag("path").not_nil!
      key = c.tag("key").not_nil!
      pending_path = "#{path}.pending"

      existing = File.exists?(path) ? File.read(path) : ""
      lines = existing.lines(chomp: true).reject { |line| line.strip.starts_with?("#{key}=") }
      new_value = String.new(s.ciphertext)
      lines << "#{key}=#{new_value}"

      File.write(pending_path, lines.join('\n') + "\n", perm: 0o600)
    end

    def verify(c : Domain::Credential, s : Domain::NewSecret) : Bool
      path = c.tag("path").not_nil!
      key = c.tag("key").not_nil!
      pending_path = "#{path}.pending"
      return false unless File.exists?(pending_path)

      content = File.read(pending_path)
      expected_line = "#{key}=#{String.new(s.ciphertext)}"
      content.includes?(expected_line) && content.bytesize > 0
    end

    def commit(c : Domain::Credential, s : Domain::NewSecret) : Nil
      _ = s
      path = c.tag("path").not_nil!
      pending_path = "#{path}.pending"
      raise RotatorError.new("pending file missing at commit time: #{pending_path}") unless File.exists?(pending_path)
      File.rename(pending_path, path)
    end

    def rollback_apply(c : Domain::Credential, s : Domain::NewSecret) : Nil
      _ = s
      path = c.tag("path").not_nil!
      pending_path = "#{path}.pending"
      File.delete(pending_path) if File.exists?(pending_path)
    end
  end
end
