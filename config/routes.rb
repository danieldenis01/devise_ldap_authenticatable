require 'rails'
Rails.application.routes.draw do
  resources :syncronizers do
    collection do
      post 'renew'
    end
  end
end
