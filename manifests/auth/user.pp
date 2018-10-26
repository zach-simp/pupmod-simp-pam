define pam::auth::user (
  Array[String]                               $users,
  Array[String]                               $token_type,
  Variant[Enum['-','+'], Integer[0,99999999]] $pin,
  Array[String]                               $secret_key
) {
  include '::pam::auth'
  $_separator = '\t'
  $_name = regsubst($name, '/', '_')
  $_token_type = join($token_type, $_separator)
  $_users = join($users, $_separator)
  $_pin = join($pin, $_separator)

  $_content = "${_token_type}${_users}${_pin}${secret_key}"

  concat::fragment { "pam_oath_user_${_name}":
    target  => '/etc/liboath/users.oath',
    content => $_content
  }
}
  
