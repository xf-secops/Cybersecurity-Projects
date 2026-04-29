# ===================
# ©AngelaMos | 2026
# dsl.cr
# ===================

require "./builder"
require "./policy"

# Top-level `policy` method makes the DSL feel native:
#
#     require "cre/policy/dsl"
#
#     policy "production-databases" do
#       description "All prod DB credentials rotate every 30 days"
#       match { |c| c.kind.database? && c.tag(:env) == "prod" }
#       max_age 30.days
#       enforce :rotate_immediately
#       notify_via :telegram, :structured_log
#     end
#
# The `with builder yield` makes every Builder method (description, match,
# max_age, enforce, notify_via, on_rotation_failure, on_drift_detected) callable
# without a receiver inside the block. Symbol literals autocast to enum values
# so typos like `enforce :rotate_immediatly` fail at compile time.
def policy(name : String, &block)
  builder = CRE::Policy::Builder.new(name)
  with builder yield
  CRE::Policy::REGISTRY << builder.build
end
