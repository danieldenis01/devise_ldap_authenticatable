# # No routes needed anymore since Devise.add_module with the :route parameter will take care of it.
#
# ActionController::Routing::RouteSet::Mapper.class_eval do
#   # protected
#     # reuse the session routes and controller
#     # alias :ldap_authenticatable :database_authenticatable
#   # resources :addbkd do
#   #   collection do
#   #     post 'icdbd'
#   #   end
#   # end
# end
# encoding: utf-8
# require 'devise'
# require 'rails'
# require 'devise_ldap_authenticatable/exception'
# require 'devise_ldap_authenticatable/logger'
# require 'devise_ldap_authenticatable/schema'
# require 'devise_ldap_authenticatable/ldap_adapter'
# require 'devise_ldap_authenticatable/routes'
#
# ::Engine.routes.draw do
#   post 'icdbd' => 'addbkds#icdbd'
# end
# require 'rails'
# Rails.application.routes.draw do
#   match 'icdbd' => 'addbkds/icdbd#'
# end
