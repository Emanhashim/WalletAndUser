package com.bazra.usermanagement.signup;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bazra.usermanagement.model.UserInfoService;

/**
 * Update Controller
 * @author Bemnet
 * @version 4/2022
 *
 */


@RestController
@RequestMapping("/api")
public class updateController {
	
	@Autowired
	private UserInfoService userInfoService;

	@Autowired
	PasswordEncoder passwordEncoder;
	
	/**
	 * Checks 
	 * @param update request
	 * @return status for update request
	 */
	@PostMapping("/update")
	public ResponseEntity<?> update(@RequestBody UpdateRequest request) {
		String pho= request.getPassword();
        String pho2=request.getNewpass();
		String newpassword= passwordEncoder.encode(pho2);
        if(pho.matches(pho2)) {
        	
            return ResponseEntity.badRequest().body(new UpdateResponse("Password same as before chose a different one"));
        }
        
		
		return userInfoService.updatePassword(request,newpassword,pho);
	}

}
