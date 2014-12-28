Grails-springsecurity-custom-salt-for-password-encryption
=========================================================

Spring Security Plugin grails uses username as encryption salt . Password encryption salt is something that you need to keep it secret. In this I will show you how you could create custom salt per user and make your application security more strong.

Step 1 . First you need to follow https://github.com/abhimanyu1990/Grails-Springsecurity-username-email-login  to configure spring security in your application.

Step 2 . Edit the User domain and add a new field salt in it and add a getSalt() method in it . 

```
package com.abhimanyu.example.auth

class User {

	transient springSecurityService

	String username
	String password
	String email
	String salt 
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
	}

	static mapping = {
		password column: '`password`'
	}

	Set<Role> getAuthorities() {
		UserRole.findAllByUser(this).collect { it.role }
	}

	String getSalt() {
  	if(this.salt == null){
    	this.salt = UUID.randomUUID().toString()
  	}
		this.salt
	}
	/*def beforeInsert() {
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
			encodePassword()
		}
	}

	protected void encodePassword() {
		password = springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(password) : password
	}*/
}
```

Step 3 . Create a groovy class CustomSaltSource which will extends ReflectionSaltSource
```
package com.abhimanyu.example.auth;

import org.springframework.security.authentication.dao.ReflectionSaltSource;
import org.springframework.security.core.userdetails.UserDetails;

class CustomSaltSource extends ReflectionSaltSource {
	Object getSalt(UserDetails user) {
		user[userPropertyToUse]
	}
}
```

Step 3 . Create a new groovy class CustomUserDetails which will extend GrailsUser . 
package com.abhimanyu.example.auth
```
import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority

class CustomUserDetails extends GrailsUser {
	public final String salt

	 CustomUserDetails(String username, String password, boolean enabled,
                 boolean accountNonExpired, boolean credentialsNonExpired,
                 boolean accountNonLocked,
                 Collection<GrantedAuthority> authorities,
                 long id, String salt) {
      super(username, password, enabled, accountNonExpired,
            credentialsNonExpired, accountNonLocked, authorities, id)

      this.salt = salt
   }

   String getSalt(){
	   println "Custom salt for this user is  == "+this.salt
	   return null
   }
}
```

Step 4. Now we need to make changes in CustomUserDetailsService file we have created during spring security configuration (follow https://github.com/abhimanyu1990/Grails-Springsecurity-username-email-login )

Instead of GrailsUser we will initialize CustomUserDetails class , which accept an extra parameter salt
```
 return new GrailsUser(user.username,
			  		user.password,
                    user.enabled,
                    !user.accountExpired,
                    !user.passwordExpired,
                    !user.accountLocked,
                    authorities ?: NO_ROLES,
                    user.id)
                    
```


Remove the above code with below code 
```
 return new CustomUserDetails(user.username, user.password, user.enabled,
			!user.accountExpired, !user.passwordExpired,
			!user.accountLocked, authorities ?: NO_ROLES, user.id,
			user.salt)
```
Step 5 : Now add below line to your Config.groovy  file , so that Spring Security will use "salt" filed for password encoding and decoding
```
grails.plugin.springsecurity.dao.reflectionSaltSourceProperty = 'salt'
```
Step 6 : You need to use same salt for password encryption while updating the password or registering a new user that is/will be saved in the salt filed

Step 7 : now we need to modify our BootStrap.groovy , to use custom salt 
genearate a String using UUID.randomUUID().toString() to encode the password and save the same field in "salt" field of user so that it will be use by spring security while decoding .

BootStrap.groovy
```
import com.abhimanyu.example.auth.Role
import com.abhimanyu.example.auth.User
import com.abhimanyu.example.auth.UserRole
import grails.plugin.springsecurity.authentication.dao.NullSaltSource

class BootStrap {

    def saltSource
	def springSecurityService
	def grailsApplication
    def init = { servletContext ->
		if(Role.list().size() == 0){
				new Role(authority:"ROLE_SUPERADMIN").save()
				new Role(authority:"ROLE_ADMIN").save()
					
		}
				
		if(User.list().size() == 0){
			String customSalt = UUID.randomUUID().toString();
			String salt = saltSource instanceof NullSaltSource ? null : customSalt
			String encodedPassword = springSecurityService.encodePassword('root',salt)
			def superUser = new User( email:"abhimanyu.mailme@gmail.com",
				    				  password:encodedPassword,
									  accountLocked: false,
									  enabled: true,
									  accountExpired:false,
									  passwordExpired:false,
									  username:"SUPERADMIN",
									  salt:customSalt
									)
			superUser.save()
			superUser.errors.each{
				println it
			}
			def role = new UserRole(user:superUser,role:Role.findWhere(authority:'ROLE_SUPERADMIN')).save();
			}
	
    }
    def destroy = {
    }
}

```



