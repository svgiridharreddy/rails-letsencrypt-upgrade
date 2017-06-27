# frozen_string_literal: true

require_dependency 'lets_encrypt/application_controller'

module LetsEncrypt
  # :nodoc:
  class VerificationsController < ApplicationController
    def show
      if verification_string = find_verification_string
        render plain: verification_string 
      else
        render plain: 'Verification not found', status: 404
      end
    end

    protected

    def find_verification_string
      connection = LetsEncrypt::Redis.connection
      connection.get("verification_path.#{filename}")
    end

    def filename
      ".well-known/acme-challenge/#{params[:verification_path]}"
    end
  end
end
