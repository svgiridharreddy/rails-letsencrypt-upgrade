# frozen_string_literal: true

# :nodoc:
class CreateLetsencryptCertificates < ActiveRecord::Migration<%= migration_version %>
  def change
    create_table :letsencrypt_certificates do |t|
      t.string   :domain
      t.string   :alternative_names, array: true, default: []
      t.text     :certificate, limit: 65535
      t.text     :intermediaries, limit: 65535
      t.text     :key, limit: 65535
      t.datetime :expires_at
      t.datetime :renew_after

      t.index    :domain
      t.index    :renew_after
      t.timestamps
    end
  end
end
