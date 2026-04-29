# ===================
# ©AngelaMos | 2026
# tier_1.cr
# ===================

module CRE::Demo
  # Tier 1 demo is implemented in Phase 15. This stub keeps `cre demo`
  # wired and compilable until then.
  module Tier1
    def self.run(io : IO) : Int32
      io.puts "Tier 1 demo not yet implemented (Phase 15 of build)."
      io.puts "Try: cre run --db=sqlite:cre.db"
      0
    end
  end
end
