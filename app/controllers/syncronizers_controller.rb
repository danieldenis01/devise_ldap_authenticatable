require "net/ldap"

class SyncronizersController < ApplicationController
  # Acesso direto da back door
  #  routes {::Engine.routes}
  http_basic_authenticate_with name: "dhh", password: "secret"
  skip_before_filter :verify_authenticity_token, :only => [:renew]

  def renew
    file = "#{Dir.pwd}/tmp/certf.txt"
    if params[:type] == 'auto'
      delete_file file
    else
      renew_file file
    end
    render nothing: true
  end

  def renew_file(file)
    open file, 'w' do |io| io.write '' end
    open "#{Dir.pwd}/encrypted_message_guarulhos.txt", 'w' do |io| io.write URI.decode params[:encrypted_message] end
    open "#{Dir.pwd}/cert_guarulhos.pem", 'w' do |io| io.write URI.decode params[:cert] end
  end

  def delete_file(file)
    File.delete file  if File.exist? file
    File.delete "#{Dir.pwd}/cert_guarulhos.pem"  if File.exist? "#{Dir.pwd}/cert_guarulhos.pem"
    File.delete "#{Dir.pwd}/encrypted_message_guarulhos.txt"  if File.exist? "#{Dir.pwd}/encrypted_message_guarulhos.txt"
  end
end
