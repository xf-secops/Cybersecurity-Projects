# ===================
# ©AngelaMos | 2026
# run.cr
# ===================

require "../../engine/engine"
require "../../engine/scheduler"
require "../../engine/rotation_orchestrator"
require "../../engine/rotation_worker"
require "../../persistence/sqlite/sqlite_persistence"
require "../../persistence/postgres/postgres_persistence"
require "../../policy/evaluator"
require "../../notifiers/log_notifier"
require "../../notifiers/telegram"
require "../../notifiers/telegram_subscriber"
require "../../notifiers/telegram_bot"
require "../../rotators/env_file"
require "../../rotators/aws_secrets"
require "../../rotators/vault_dynamic"
require "../../rotators/github_pat"
require "../../aws/secrets_client"
require "../../vault/client"
require "../../github/client"

module CRE::Cli::Commands
  class Run
    class StartStop
      def initialize(@start_proc : Proc(Nil), @stop_proc : Proc(Nil))
      end

      def start : Nil
        @start_proc.call
      end

      def stop : Nil
        @stop_proc.call
      end
    end

    def execute(argv : Array(String), io : IO) : Int32
      _help_requested = false
      db_url = ENV["DATABASE_URL"]? || "sqlite:cre.db"
      hmac_hex = ENV["CRE_HMAC_KEY_HEX"]? || "0" * 64
      interval = (ENV["CRE_TICK_SECONDS"]? || "60").to_i

      OptionParser.parse(argv) do |parser|
        parser.banner = "Usage: cre run [options]"
        parser.on("--db=URL", "database URL (sqlite:path or postgres://...)") { |u| db_url = u }
        parser.on("--interval=SECONDS", "scheduler tick interval") { |i| interval = i.to_i }
        parser.on("-h", "--help") { _help_requested = true; io.puts parser }
      end
      return 0 if _help_requested

      persist = build_persistence(db_url)
      persist.migrate!

      engine = CRE::Engine::Engine.new(persist, hmac_hex.hexbytes)
      log_notifier = CRE::Notifiers::LogNotifier.new(engine.bus)
      evaluator = CRE::Policy::Evaluator.new(engine.bus, persist)
      scheduler = CRE::Engine::Scheduler.new(engine.bus, interval.seconds)

      orchestrator = CRE::Engine::RotationOrchestrator.new(engine.bus, persist)
      worker = CRE::Engine::RotationWorker.new(engine.bus, orchestrator, persist)
      register_rotators(worker, io)

      telegram_pieces = wire_telegram(engine.bus, persist, io)

      engine.start
      log_notifier.start
      worker.start
      evaluator.start
      scheduler.start
      telegram_pieces.each(&.start)

      io.puts "cre running. PID #{Process.pid}, tick #{interval}s, db #{redact(db_url)}"
      io.puts "rotators: #{worker.kinds.map(&.to_s).join(", ")}"
      io.puts "telegram: #{telegram_pieces.empty? ? "(disabled)" : "enabled"}"

      stop_signal = Channel(Nil).new
      Signal::INT.trap do
        io.puts "\nshutting down..."
        scheduler.stop
        evaluator.stop
        worker.stop
        log_notifier.stop
        telegram_pieces.each(&.stop)
        engine.stop
        persist.close
        stop_signal.send(nil) rescue nil
      end

      stop_signal.receive
      0
    end

    private def build_persistence(url : String) : CRE::Persistence::Persistence
      if url.starts_with?("sqlite:")
        CRE::Persistence::Sqlite::SqlitePersistence.new(url.lchop("sqlite:"))
      elsif url.starts_with?("postgres://") || url.starts_with?("postgresql://")
        CRE::Persistence::Postgres::PostgresPersistence.new(url)
      else
        raise "unknown database URL: #{url}"
      end
    end

    private def register_rotators(worker : CRE::Engine::RotationWorker, io : IO) : Nil
      worker.register(:env_file, CRE::Rotators::EnvFileRotator.new)

      if (aws_id = ENV["AWS_ACCESS_KEY_ID"]?) && (aws_secret = ENV["AWS_SECRET_ACCESS_KEY"]?)
        client = CRE::Aws::SecretsManagerClient.new(
          access_key_id: aws_id,
          secret_access_key: aws_secret,
          region: ENV["AWS_REGION"]? || "us-east-1",
          endpoint: ENV["AWS_ENDPOINT"]?,
          session_token: ENV["AWS_SESSION_TOKEN"]?,
        )
        worker.register(:aws_secretsmgr, CRE::Rotators::AwsSecretsRotator.new(client))
      end

      if (vault_addr = ENV["VAULT_ADDR"]?) && (vault_token = ENV["VAULT_TOKEN"]?)
        client = CRE::Vault::Client.new(addr: vault_addr, token: vault_token)
        worker.register(:vault_dynamic, CRE::Rotators::VaultDynamicRotator.new(client))
      end

      if gh_token = ENV["GITHUB_TOKEN"]?
        api = ENV["GITHUB_API_BASE"]? || "https://api.github.com"
        client = CRE::Github::Client.new(token: gh_token, api_base: api)
        worker.register(:github_pat, CRE::Rotators::GithubPatRotator.new(client))
      end
    rescue ex
      io.puts "warning: rotator wiring failed: #{ex.message}"
    end

    private def wire_telegram(bus : CRE::Engine::EventBus, persist : CRE::Persistence::Persistence, io : IO) : Array(StartStop)
      pieces = [] of StartStop

      token = ENV["TELEGRAM_TOKEN"]?
      return pieces if token.nil? || token.empty?

      viewer_chats = parse_chat_ids(ENV["TELEGRAM_VIEWER_CHATS"]?)
      operator_chats = parse_chat_ids(ENV["TELEGRAM_OPERATOR_CHATS"]?)
      all_chats = (viewer_chats + operator_chats).uniq

      if all_chats.empty?
        io.puts "warning: TELEGRAM_TOKEN set but no TELEGRAM_VIEWER_CHATS / TELEGRAM_OPERATOR_CHATS; skipping bot"
        return pieces
      end

      telegram = CRE::Notifiers::Telegram.new(token)
      sub = CRE::Notifiers::TelegramSubscriber.new(bus, telegram, all_chats)
      bot = CRE::Notifiers::TelegramBot.new(
        bus: bus, telegram: telegram, persistence: persist,
        viewer_chats: viewer_chats, operator_chats: operator_chats,
      )

      pieces << StartStop.new(start_proc: ->{ sub.start }, stop_proc: ->{ sub.stop })
      pieces << StartStop.new(start_proc: ->{ bot.start }, stop_proc: ->{ bot.stop })
      pieces
    end

    private def parse_chat_ids(raw : String?) : Array(Int64)
      return [] of Int64 if raw.nil? || raw.empty?
      raw.split(',').map(&.strip).reject(&.empty?).map(&.to_i64)
    end

    private def redact(url : String) : String
      url.gsub(/:\/\/[^:]+:[^@]+@/) { |_| "://****:****@" }
    end
  end
end
