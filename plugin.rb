# frozen_string_literal: true

# name: DiscourseJwtSession
# about: Store the user's session details in a JWT cookie, in addition to the primary session cookie, so it can be accessed from other sites on your domain
# version: 1.0
# authors: wilson29thid
# url: https://github.com/29th/discourse-jwt-session

enabled_site_setting :jwt_session_enabled

PLUGIN_NAME ||= "DiscourseJwtSession"

after_initialize do
  class JwtCurrentUserProvider < Auth::DefaultCurrentUserProvider
    def set_auth_cookie!(unhashed_auth_token, user, cookie_jar)
      super

      cookie_name = SiteSetting.jwt_session_cookie_name
      secret_key = GlobalSetting.safe_secret_key_base
      algorithm = "HS256"

      jwt_payload = {
        sub: "#{user.id}@comfortfoodie.club",
        exp: SiteSetting.maximum_session_age.hours.from_now.to_i
      }
      jwt = JWT.encode(jwt_payload, secret_key, algorithm)

      if SiteSetting.persistent_sessions
        expires = SiteSetting.maximum_session_age.hours.from_now
      end

      if SiteSetting.same_site_cookies != "Disabled"
        same_site = SiteSetting.same_site_cookies
      end

      cookie_jar[cookie_name] = {
        value: jwt,
        httponly: false,
        secure: SiteSetting.force_https,
        expires: expires,
        same_site: same_site,
        domain: :all
      }
    end

    def log_off_user(session, cookie_jar)
      super

      cookie_name = SiteSetting.jwt_session_cookie_name
      cookie_jar.delete(cookie_name, domain: :all)
    end
  end

  Discourse.current_user_provider = JwtCurrentUserProvider
end
