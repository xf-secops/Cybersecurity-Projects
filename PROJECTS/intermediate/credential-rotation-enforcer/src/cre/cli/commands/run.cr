# ===================
# ©AngelaMos | 2026
# run.cr
# ===================

require "../../engine/engine"
require "../../engine/scheduler"
require "../../persistence/sqlite/sqlite_persistence"
require "../../persistence/postgres/postgres_persistence"
require "../../policy/evaluator"
require "../../notifiers/log_notifier"

module CRE::Cli::Commands
  class Run
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

      engine.start
      log_notifier.start
      evaluator.start
      scheduler.start

      io.puts "cre running. PID #{Process.pid}, tick #{interval}s, db #{redact(db_url)}"

      Signal::INT.trap do
        io.puts "\nshutting down..."
        scheduler.stop
        evaluator.stop
        log_notifier.stop
        engine.stop
        persist.close
        exit 0
      end

      sleep
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

    private def redact(url : String) : String
      url.gsub(/:(\/{2,})([^:@]+):([^@]+)@/) { |_| ":#{$1}#{$2}:****@" }
    end
  end
end
