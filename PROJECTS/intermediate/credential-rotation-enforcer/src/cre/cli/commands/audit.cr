# ===================
# ©AngelaMos | 2026
# audit.cr
# ===================

require "../../audit/audit_log"
require "../../persistence/sqlite/sqlite_persistence"

module CRE::Cli::Commands
  class Audit
    def execute(argv : Array(String), io : IO) : Int32
      sub = argv.shift?
      case sub
      when "verify" then verify(argv, io)
      when nil, "--help", "-h"
        io.puts "Usage: cre audit verify [--db=PATH]"
        0
      else
        io.puts "unknown audit subcommand: #{sub}"
        64
      end
    end

    private def verify(argv : Array(String), io : IO) : Int32
      db_path = ENV["CRE_DB_PATH"]? || "cre.db"
      hmac_hex = ENV["CRE_HMAC_KEY_HEX"]? || "0" * 64

      OptionParser.parse(argv) do |parser|
        parser.on("--db=PATH", "") { |p| db_path = p }
      end

      persist = CRE::Persistence::Sqlite::SqlitePersistence.new(db_path)
      persist.migrate!

      log = CRE::Audit::AuditLog.new(persist, hmac_hex.hexbytes, 1, 1024)
      ok = log.verify_chain
      latest_seq = persist.audit.latest_seq
      persist.close

      if ok
        io.puts "✓ audit chain valid: #{latest_seq} entries"
        0
      else
        io.puts "✗ audit chain BROKEN — verification failed"
        2
      end
    end
  end
end
