# ===================
# ©AngelaMos | 2026
# bundle.cr
# ===================

require "../persistence/persistence"

module CRE::Compliance
  # Bundle is implemented in Phase 14. This stub keeps the CLI export
  # subcommand wired and compilable until then.
  class Bundle
    def initialize(@persistence : Persistence::Persistence, @framework : String)
    end

    def write(path : String) : Nil
      raise NotImplementedError.new("Compliance::Bundle.write will be wired up in Phase 14")
    end
  end
end
