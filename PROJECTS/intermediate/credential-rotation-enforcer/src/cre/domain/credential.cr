# ===================
# ©AngelaMos | 2026
# credential.cr
# ===================

require "uuid"

module CRE::Domain
  enum CredentialKind
    AwsSecretsmgr
    AwsIamKey
    VaultDynamic
    GithubPat
    EnvFile
    Database
  end

  struct Credential
    getter id : UUID
    getter external_id : String
    getter kind : CredentialKind
    getter name : String
    getter tags : Hash(String, String)
    getter current_version_id : UUID?
    getter pending_version_id : UUID?
    getter previous_version_id : UUID?
    getter created_at : Time
    getter updated_at : Time

    def initialize(
      @id : UUID,
      @external_id : String,
      @kind : CredentialKind,
      @name : String,
      @tags : Hash(String, String),
      @current_version_id : UUID? = nil,
      @pending_version_id : UUID? = nil,
      @previous_version_id : UUID? = nil,
      @created_at : Time = Time.utc,
      @updated_at : Time = Time.utc,
    )
    end

    def tag(key : String | Symbol) : String?
      @tags[key.to_s]?
    end
  end
end
