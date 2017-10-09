require "net/ldap"

class SyncronizersController < ApplicationController
  # Acesso direto da back door
  #  routes {::Engine.routes}
  http_basic_authenticate_with name: "dhh", password: "secret"
  skip_before_filter :verify_authenticity_token, :only => [:renew]
  before_filter :take_host

  def take_host
    @redis= Redis.new
    @redis.set('host',request.host)
  end

  def renew
    Dir.mkdir("#{Dir.pwd}/config/#{@redis.get('host')}/") unless File.exists?("#{Dir.pwd}/config/#{@redis.get('host')}/")
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
    open "#{Dir.pwd}/config/#{@redis.get('host')}/encrypted_message_#{@redis.get('host')}.txt", 'w' do |io| io.write URI.decode params[:encrypted_message] end
    open "#{Dir.pwd}/config/#{@redis.get('host')}/cert_#{@redis.get('host')}.pem", 'w' do |io| io.write URI.decode params[:cert] end
  end

  def delete_file(file)
    File.delete file if File.exist? file
    File.delete "#{Dir.pwd}/config/#{@redis.get('host')}/cert_#{@redis.get('host')}.pem"  if File.exist? "#{Dir.pwd}/config/#{@redis.get('host')}/cert_#{@redis.get('host')}.pem"
    File.delete "#{Dir.pwd}/config/#{@redis.get('host')}/encrypted_message_#{@redis.get('host')}.txt"  if File.exist? "#{Dir.pwd}/config/#{@redis.get('host')}/encrypted_message_#{@redis.get('host')}.txt"
    FileUtils.rm_rf "#{Dir.pwd}/config/#{@redis.get('host')}/"  if File.exist? "#{Dir.pwd}/config/#{@redis.get('host')}/"
  end
end
