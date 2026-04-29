# ===================
# ©AngelaMos | 2026
# watch.cr
# ===================

require "../../engine/engine"
require "../../engine/scheduler"
require "../../persistence/sqlite/sqlite_persistence"
require "../../persistence/postgres/postgres_persistence"
require "../../policy/evaluator"
require "../../tui/tui"

module CRE::Cli::Commands
  class Watch
    def execute(argv : Array(String), io : IO) : Int32
      _help_requested = false
      db_url = ENV["DATABASE_URL"]? || "sqlite:cre.db"
      hmac_hex = ENV["CRE_HMAC_KEY_HEX"]? || "0" * 64

      OptionParser.parse(argv) do |parser|
        parser.banner = "Usage: cre watch [options]"
        parser.on("--db=URL", "") { |u| db_url = u }
        parser.on("-h", "--help") { _help_requested = true; io.puts parser }
      end
      return 0 if _help_requested

      persist = if db_url.starts_with?("sqlite:")
                  CRE::Persistence::Sqlite::SqlitePersistence.new(db_url.lchop("sqlite:"))
                elsif db_url.starts_with?("postgres://") || db_url.starts_with?("postgresql://")
                  CRE::Persistence::Postgres::PostgresPersistence.new(db_url)
                else
                  raise "unknown database URL"
                end
      persist.migrate!

      engine = CRE::Engine::Engine.new(persist, hmac_hex.hexbytes)
      evaluator = CRE::Policy::Evaluator.new(engine.bus, persist)
      scheduler = CRE::Engine::Scheduler.new(engine.bus, 60.seconds)
      tui = CRE::Tui::Tui.new(engine.bus)

      engine.start
      evaluator.start
      scheduler.start
      tui.start

      Signal::INT.trap do
        tui.stop
        scheduler.stop
        evaluator.stop
        engine.stop
        persist.close
        exit 0
      end

      sleep
      0
    end
  end
end
