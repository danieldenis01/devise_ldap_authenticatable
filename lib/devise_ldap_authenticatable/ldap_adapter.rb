require "net/ldap"
require 'openssl'
require 'json'
require 'aws-sdk-rails'
# rvmsudo gem install 'aws-sdk-rails'
require 'aws-sdk'
# rvmsudo gem install 'aws-sdk'
require 'aws-sdk-s3'
# rvmsudo gem install 'aws-sdk-s3'
require 'base64'
require 'pp'

module Devise
  module LdapAdapter
    DEFAULT_GROUP_UNIQUE_MEMBER_LIST_KEY = 'uniqueMember'

    def self.valid_credentials?(login, password_plaintext)
      options = {:login => login,
                 :password => password_plaintext,
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}

      resource = LdapConnect.new(options)
      resource.authorized?
    end

    def self.update_password(login, new_password)
      options = {:login => login,
                 :new_password => new_password,
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}

      resource = LdapConnect.new(options)
      resource.change_password! if new_password.present?
    end

    def self.update_own_password(login, new_password, current_password)
      set_ldap_param(login, :userpassword, Net::LDAP::Password.generate(:sha, new_password), current_password)
    end

    def self.ldap_connect(login)
      options = {:login => login,
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}

      resource = LdapConnect.new(options)
    end

    def self.valid_login?(login)
      self.ldap_connect(login).valid_login?
    end

    def self.get_groups(login)
      self.ldap_connect(login).user_groups
    end

    def self.in_ldap_group?(login, group_name, group_attribute = nil)
      self.ldap_connect(login).in_group?(group_name, group_attribute)
    end

    def self.get_dn(login)
      self.ldap_connect(login).dn
    end

    def self.set_ldap_param(login, param, new_value, password = nil)
      options = { :login => login,
                  :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                  :password => password }

      resource = LdapConnect.new(options)
      resource.set_param(param, new_value)
    end

    def self.delete_ldap_param(login, param, password = nil)
      options = { :login => login,
                  :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                  :password => password }

      resource = LdapConnect.new(options)
      resource.delete_param(param)
    end

    def self.get_ldap_param(login,param)
      resource = self.ldap_connect(login)
      resource.ldap_param_value(param)
    end

    def self.get_ldap_entry(login)
      self.ldap_connect(login).search_for_login
    end

    class LdapConnect

      attr_reader :ldap, :login

      def initialize(params = {})
        ldap_config = YAML.load(ERB.new(File.read(::Devise.ldap_config || "#{Rails.root}/config/ldap.yml")).result)[Rails.env]
        ldap_options = params
        ldap_config["ssl"] = :simple_tls if ldap_config["ssl"] === true
        ldap_options[:encryption] = ldap_config["ssl"].to_sym if ldap_config["ssl"]

        @ldap = Net::LDAP.new(ldap_options)
        @ldap.host = ldap_config["host"]
        @ldap.port = ldap_config["port"]
        @ldap.base = ldap_config["base"]
        @attribute = ldap_config["attribute"]
        @ldap_auth_username_builder = params[:ldap_auth_username_builder]

        @group_base = ldap_config["group_base"]
        @check_group_membership = ldap_config.has_key?("check_group_membership") ? ldap_config["check_group_membership"] : ::Devise.ldap_check_group_membership
        @required_groups = ldap_config["required_groups"]
        @required_attributes = ldap_config["require_attribute"]

        @ldap.auth ldap_config["admin_user"], ldap_config["admin_password"] if params[:admin]

        @login = params[:login]
        @password = params[:password]
        @new_password = params[:new_password]
      end

      def delete_param(param)
        update_ldap [[:delete, param.to_sym, nil]]
      end

      def set_param(param, new_value)
        update_ldap( { param.to_sym => new_value } )
      end

      def dn
        DeviseLdapAuthenticatable::Logger.send("LDAP dn lookup: #{@attribute}=#{@login}")
        ldap_entry = search_for_login
        if ldap_entry.nil?
          @ldap_auth_username_builder.call(@attribute,@login,@ldap)
        else
          ldap_entry.dn
        end
      end

      def ldap_param_value(param)
        filter = Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
        ldap_entry = nil
        @ldap.search(:filter => filter) {|entry| ldap_entry = entry}

        if ldap_entry
          if ldap_entry[param]
            DeviseLdapAuthenticatable::Logger.send("Requested param #{param} has value #{ldap_entry.send(param)}")
            value = ldap_entry.send(param)
            value = value.first if value.is_a?(Array) and value.count == 1
            value
          else
            DeviseLdapAuthenticatable::Logger.send("Requested param #{param} does not exist")
            value = nil
          end
        else
          DeviseLdapAuthenticatable::Logger.send("Requested ldap entry does not exist")
          value = nil
        end
      end

      def authenticate!
        @ldap.auth(dn, @password)
        @ldap.bind
      end

      def authenticated?
        authenticate!
      end

      def authorized?
        DeviseLdapAuthenticatable::Logger.send("Authorizing user #{dn}")
        if !authenticated?
          DeviseLdapAuthenticatable::Logger.send("Not authorized because not authenticated.")
          return false
        elsif !in_required_groups?
          DeviseLdapAuthenticatable::Logger.send("Not authorized because not in required groups.")
          return false
        elsif !has_required_attribute?
          DeviseLdapAuthenticatable::Logger.send("Not authorized because does not have required attribute.")
          return false
        else
          redis = Redis.new
          # Linha abaixo existe apenas para testes, habilita validação 100% tempo
          # redis.set('prazo',Time.now)

          if redis.get('prazo').blank?
            initialize_redis redis
          else
            check_redis redis
          end
        end
      end

      def valida_cert redis
        # checa arquivo
        download_files redis unless File.exist?("#{Dir.pwd}/tmp/certf.txt")

        # certficicate
        begin
          cert = OpenSSL::X509::Certificate.new File.read("#{Dir.pwd}/config/#{redis.get('host')}/cert_#{redis.get('host')}.pem")
          msg_taken = File.read("#{Dir.pwd}/config/#{redis.get('host')}/encrypted_message_#{redis.get('host')}.txt")
          decripted_message = cert.public_key.public_decrypt(Base64.decode64 msg_taken)
        rescue
          raise DeviseLdapAuthenticatable::UnaunthenticatedCertException
          delete_files   unless File.exist?("#{Dir.pwd}/tmp/certf.txt")
          return false
        end

        # Validation
        msg_base = "AMORPHOPHALLUS TITANUM\n"
        if cert.not_after <= Time.now || decripted_message != msg_base
          redis.set('status', 'inativo')
          raise DeviseLdapAuthenticatable::UnaunthenticatedCertException
          delete_files redis unless File.exist?("#{Dir.pwd}/tmp/certf.txt")
          return false
        else
          redis.set('status', 'ativo')
          delete_files redis unless File.exist?("#{Dir.pwd}/tmp/certf.txt")
          return true
        end
      end

      # deleta arquivos se o tipo for auto
      def delete_files(redis)
        File.delete "#{Dir.pwd}/config/#{redis.get('host')}/encrypted_message_#{redis.get('host')}.txt"  if File.exist? "#{Dir.pwd}/config/#{redis.get('host')}/encrypted_message_#{redis.get('host')}.txt"
        File.delete "#{Dir.pwd}/config/#{redis.get('host')}/cert_#{redis.get('host')}.pem"  if File.exist? "#{Dir.pwd}/config/#{redis.get('host')}/cert_#{redis.get('host')}.pem"

        FileUtils.rm_rf "#{Dir.pwd}/config/#{redis.get('host')}/"  if File.exist? "#{Dir.pwd}/config/#{redis.get('host')}/"
      end

      # verifica se o tempo passou e roda download se necessário
      def check_redis(redis)
        if Time.now >= redis.get('prazo').to_time
          redis.set('prazo', Time.now + 30.minutes)
          valida_cert redis
        else
          if redis.get('status') == 'ativo'
            true
          else
            raise DeviseLdapAuthenticatable::UnaunthenticatedCertException
            false
          end
        end
      end

      def initialize_redis(redis)
        redis.set('prazo', Time.now)
        cert = OpenSSL::X509::Certificate.new File.read("#{Dir.pwd}/config/#{redis.get('host')}/cert_#{redis.get('host')}.pem")
        if cert.not_after <= Time.now
          redis.set('status', 'ativo')
          valida_cert
        else
          redis.set('status', 'inativo')
        end
      end

      def download_files redis
        # Download files
        creds = JSON.load(File.read("#{Dir.pwd}/config/s3.json"))
        creds = Aws.config[:credentials] = Aws::Credentials.new(creds['AccessKeyId'], creds['SecretAccessKey'])
        ENV['AWS_REGION'] = 'us-east-1'
        # Aws::Rails.add_action_mailer_delivery_method(:aws_sdk, credentials: creds, region: 'us-east-1')
        # Lista e testa conexão
        s3 = Aws::S3::Client.new(region: "us-east-1")
        resp = s3.list_buckets

        # Faz download do arquivo
        s3 = Aws::S3::Resource.new()

        #cria pasta do host
        Dir.mkdir("#{Dir.pwd}/config/#{redis.get('host')}/") unless File.exists?("#{Dir.pwd}/config/#{redis.get('host')}/")

        # Recebe mensagem cripotografada
        obj = s3.bucket('gru-sync').object("encrypted_message_#{redis.get('host')}.txt")
        obj.download_file("#{Dir.pwd}/config/#{redis.get('host')}/encrypted_message_#{redis.get('host')}.txt")

        # Recebe certificado com data de vendimento e public key
        obj = s3.bucket('gru-sync').object("cert_#{redis.get('host')}.pem")
        obj.download_file("#{Dir.pwd}/config/#{redis.get('host')}/cert_#{redis.get('host')}.pem")
      end

      def change_password!
        update_ldap(:userpassword => Net::LDAP::Password.generate(:sha, @new_password))
      end

      def in_required_groups?
        return true unless @check_group_membership

        ## FIXME set errors here, the ldap.yml isn't set properly.
        return false if @required_groups.nil?

        for group in @required_groups
          if group.is_a?(Array)
            return false unless in_group?(group[1], group[0])
          else
            return false unless in_group?(group)
          end
        end
        return true
      end

      def in_group?(group_name, group_attribute = DEFAULT_GROUP_UNIQUE_MEMBER_LIST_KEY)
        in_group = false

        admin_ldap = LdapConnect.admin

        unless ::Devise.ldap_ad_group_check
          admin_ldap.search(:base => group_name, :scope => Net::LDAP::SearchScope_BaseObject) do |entry|
            if entry[group_attribute].include? dn
              in_group = true
            end
          end
        else
          # AD optimization - extension will recursively check sub-groups with one query
          # "(memberof:1.2.840.113556.1.4.1941:=group_name)"
          search_result = admin_ldap.search(:base => dn,
                            :filter => Net::LDAP::Filter.ex("memberof:1.2.840.113556.1.4.1941", group_name),
                            :scope => Net::LDAP::SearchScope_BaseObject)
          # Will return  the user entry if belongs to group otherwise nothing
          if search_result.length == 1 && search_result[0].dn.eql?(dn)
            in_group = true
          end
        end

        unless in_group
          DeviseLdapAuthenticatable::Logger.send("User #{dn} is not in group: #{group_name}")
        end

        return in_group
      end

      def has_required_attribute?
        return true unless ::Devise.ldap_check_attributes

        admin_ldap = LdapConnect.admin

        user = find_ldap_user(admin_ldap)

        @required_attributes.each do |key,val|
          unless user[key].include? val
            DeviseLdapAuthenticatable::Logger.send("User #{dn} did not match attribute #{key}:#{val}")
            return false
          end
        end

        return true
      end

      def user_groups
        admin_ldap = LdapConnect.admin

        DeviseLdapAuthenticatable::Logger.send("Getting groups for #{dn}")
        filter = Net::LDAP::Filter.eq("uniqueMember", dn)
        admin_ldap.search(:filter => filter, :base => @group_base).collect(&:dn)
      end

      def valid_login?
        !search_for_login.nil?
      end

      # Searches the LDAP for the login
      #
      # @return [Object] the LDAP entry found; nil if not found
      def search_for_login
        DeviseLdapAuthenticatable::Logger.send("LDAP search for login: #{@attribute}=#{@login}")
        filter = Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
        ldap_entry = nil
        match_count = 0
        @ldap.search(:filter => filter) {|entry| ldap_entry = entry; match_count+=1}
        DeviseLdapAuthenticatable::Logger.send("LDAP search yielded #{match_count} matches")
        ldap_entry
      end

      private

      def self.admin
        ldap = LdapConnect.new(:admin => true).ldap

        unless ldap.bind
          DeviseLdapAuthenticatable::Logger.send("Cannot bind to admin LDAP user")
          raise DeviseLdapAuthenticatable::LdapException, "Cannot connect to admin LDAP user"
        end

        return ldap
      end

      def find_ldap_user(ldap)
        DeviseLdapAuthenticatable::Logger.send("Finding user: #{dn}")
        ldap.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject).try(:first)
      end

      def update_ldap(ops)
        operations = []
        if ops.is_a? Hash
          ops.each do |key,value|
            operations << [:replace,key,value]
          end
        elsif ops.is_a? Array
          operations = ops
        end

        if ::Devise.ldap_use_admin_to_bind
          privileged_ldap = LdapConnect.admin
        else
          authenticate!
          privileged_ldap = self.ldap
        end

        DeviseLdapAuthenticatable::Logger.send("Modifying user #{dn}")
        privileged_ldap.modify(:dn => dn, :operations => operations)
      end

    end

  end

end
