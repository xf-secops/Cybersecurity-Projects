# ===================
# ©AngelaMos | 2026
# rotate.cr
# ===================

require "../../engine/event_bus"
require "../../engine/rotation_orchestrator"
require "../../persistence/sqlite/sqlite_persistence"
require "../../rotators/env_file"

module CRE::Cli::Commands
  class Rotate
    def execute(argv : Array(String), io : IO) : Int32
      _help_requested = false
      db_url = ENV["DATABASE_URL"]? || "sqlite:cre.db"
      cred_id_str = nil

      OptionParser.parse(argv) do |parser|
        parser.banner = "Usage: cre rotate <credential-id> [options]"
        parser.on("--db=URL", "") { |u| db_url = u }
        parser.on("-h", "--help") { _help_requested = true; io.puts parser }
        parser.unknown_args { |args| cred_id_str = args.first? }
      end
      return 0 if _help_requested

      if cred_id_str.nil?
        io.puts "usage: cre rotate <credential-id>"
        return 64
      end

      cred_id = UUID.new(cred_id_str.not_nil!) rescue nil
      if cred_id.nil?
        io.puts "invalid credential id"
        return 64
      end

      persist = if db_url.starts_with?("sqlite:")
                  CRE::Persistence::Sqlite::SqlitePersistence.new(db_url.lchop("sqlite:"))
                else
                  raise "rotate currently supports SQLite only via CLI shortcut"
                end
      persist.migrate!

      cred = persist.credentials.find(cred_id)
      if cred.nil?
        io.puts "credential not found: #{cred_id}"
        return 1
      end

      rotator_class = CRE::Rotators::Rotator.for(rotator_kind_for(cred.kind))
      if rotator_class.nil?
        io.puts "no rotator registered for kind=#{cred.kind}"
        return 1
      end

      bus = CRE::Engine::EventBus.new
      bus.run
      orchestrator = CRE::Engine::RotationOrchestrator.new(bus, persist)

      rotator = case cred.kind
                when CRE::Domain::CredentialKind::EnvFile then CRE::Rotators::EnvFileRotator.new
                else
                  raise "this CLI shortcut only supports env_file via direct rotation; cloud rotators need full daemon config"
                end

      io.puts "Rotating #{cred.name} (#{cred.id}) via #{rotator.kind}..."
      state = orchestrator.run(cred, rotator)
      sleep 0.1.seconds
      bus.stop
      persist.close

      case state
      when CRE::Persistence::RotationState::Completed then io.puts "✓ rotation completed"; 0
      when CRE::Persistence::RotationState::Failed    then io.puts "✗ rotation failed"; 1
      else                                                 io.puts "rotation ended in unexpected state #{state}"; 2
      end
    end

    private def rotator_kind_for(kind : CRE::Domain::CredentialKind) : Symbol
      case kind
      in .aws_secretsmgr? then :aws_secretsmgr
      in .vault_dynamic?  then :vault_dynamic
      in .github_pat?     then :github_pat
      in .env_file?       then :env_file
      in .aws_iam_key?    then :aws_iam_key
      in .database?       then :database
      end
    end
  end
end
