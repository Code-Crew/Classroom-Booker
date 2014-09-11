<?php  if (!defined('BASEPATH')) exit('No direct script access allowed');

/**
 * Code Igniter User Authentication Class
 * By Craig Rodway, craig.rodway@gmail.com
 */





// User types
define( 'ADMINISTRATOR', 1 ) ;
define( 'TEACHER', 2 ) ;




class Userauth{



	
	var $object;
	var $timestamp;
	var $allowed_users = array();
	var $denied_users = array();
	var $allowed_set = false;
	var $denied_set = false;
	var $acl_denied = 'You are not permitted to view this page.';




	function Userauth(){
		$this->object =& get_instance();
		$this->object->load->database();
		$this->timestamp = mdate("%Y-%m-%d %H:%i:%s");
		log_message('debug','User Authentication Class Initialised via '.get_class($this->object));
	}




	/**
	 * Logout user and reset session data
	 */
	function logout(){
		log_message('debug','Userauth: Logout: '.$this->object->session->userdata('username'));
		$sessdata = array('username'=>'', 'loggedin'=>'false', 'schoolcode'=>'');
		$this->object->session->set_userdata($sessdata);
		$this->object->session->destroy();
		#redirect('user/login','location');
	}




	/**
	 * Try and validate a login and optionally set session data
	 *
	 * @param		string		$username					Username to login
	 * @param		string		$password					Password to match user
	 * @param		bool			$session (true)		Set session data here. False to set your own
	 */
	 
	
 
	function sessionFromRow($row) {
		$session_data = array(
			'user_id' => $row->user_id,
			'username' => $row->username,
			'schoolname' => $row->name,
			'displayname' => $row->displayname,
			'school_id' => $row->school_id,
			'loggedin' => 'true',
			'hash' => sha1('c0d31gn1t3r'.$this->timestamp.$row->username)
		);
		$this->object->session->set_userdata($session_data);	
	}
	
	function fromldap($info) {
		$data = array(
			'username' => $info[0],
			'email' => $info[1],
			'firstname' => $info[2],
			'lastname' => $info[3],
			'displayname' => $info[4],
			'password' => 'LDAP',
			'lastlogin' => $this->timestamp,
			'authlevel' => TEACHER,
			'enabled' => 1,		
			'school_id' => 1,
			'department_id' => 0,
			'ext' => NULL,
		);
		$this->object->db->insert('users', $data);		
	}
	
	 function tryassign($ldap_uname, $username, $password) {
		 if( strlen( $password ) != 40 ){ $password = sha1( $password ); }
		 $query = $this->object->db->query("SELECT users.*, school.* FROM users, school WHERE users.password='{$password}' AND users.username='{$username}' AND school.school_id=users.school_id LIMIT 1");
		 $count = $query->num_rows();
		 if($count != 1) { return false; }
		 
		 $row = $query->row();
		 if(($row->password == "LDAP") || ($row->user_id == 1)) { return false; }
		 
		$data = array(
			'username' => $ldap_uname,
			'lastlogin' => $this->timestamp,
			'password' => 'LDAP'
		);		
		$this->object->db->where('username', $username);
		$this->object->db->update('users', $data);		
		$this->sessionFromRow($row);
		 
		 return true;
	 }
	 
	function trylogin($username, $password) {
		if( $username == '' && $password == '') { return false; }
		if( strlen( $password ) != 40 ){ $password = sha1( $password ); }
		$config =& get_config();
	
		// Check to see if user is ID1 (ie, local admin) and allow access
		$query = $this->object->db->query("SELECT users.*, school.* FROM users, school WHERE users.user_id=1 AND users.username='{$username}' AND users.password='{$password}' AND school.school_id=users.school_id LIMIT 1");
		$count = $query->num_rows();
		$row = $query->row();
		if($count == 1) { $this->sessionFromRow($row); return true; }
		
		// Check login info for LDAP
		$ldap = ldap_connect("ldap://{$config['ldap_server']}") or die("Could not connect to LDAP server.");
		$bind = @ldap_bind($ldap, "{$config['ldap_login_prefix']}{$username}{$config['ldap_login_postfix']}", $password);		
		if(!$bind) { return false; }
		
		// Search for user in LDAP to confirm access
		$sr=ldap_search($ldap, $config['ldap_search_dn'], "(sAMAccountName={$username})", array('name', 'uSNCreated', 'displayName', 'userPrincipalName', 'givenName', 'sn'));
		$info = ldap_get_entries($ldap, $sr);
		if($info['count'] < 1) { return false; }
		
		// Search SQL for assigned account
		$query = $this->object->db->query("SELECT users.*, school.* FROM users, school WHERE users.username='{$username}' AND school.school_id=users.school_id LIMIT 1");
		$count = $query->num_rows();
		if($count == 1) {
			$row = $query->row();
			$row->lastlogin = $this->timestamp;
			$this->object->db->where('username', $username);
			$this->object->db->update('users', array('lastlogin' => $this->tampstamp));
			$this->sessionFromRow($row);
			return true;
		}
		
		// Assign/Create account for LDAP user
		if($config['ldap_auto_create']) {
			fromldap(array($username, $info[0]['userprincipalname'][0], $info[0]['givenname'][0], $info[0]['sn'][0], $info[0]['displayname'][0]));
			$obj = new stdClass();
			$obj->username = $username;
			$obj->email = $info[0]['userprincipalname'][0];
			$obj->firstname = $info[0]['givenname'][0];
			$obj->lastname = $info[0]['sn'][0];
			$obj->displayname = $info[0]['displayname'][0];
			$obj->password = "LDAP";
			$obj->lastlogin = $this->timestamp;
			$obj->authlevel = TEACHER;
			$obj->enabled = 1;
			$obj->school_id = 1;
			$obj->department_id = 0;
			$obj->ext = NULL;
			$this->sessionFromRow($obj);
			return true;
		} else {
			$info_str = "{$username}||{$info[0]['userprincipalname'][0]}||{$info[0]['givenname'][0]}||{$info[0]['sn'][0]}||{$info[0]['displayname'][0]}";
			$this->object->session->set_flashdata('ldap_data',$info_str);
			redirect('login/assign', 'location');				
		}
	}
	 

	function CheckAuthLevel( $allowed, $level = NULL ){
		if($level == NULL){
			#$level = $this->getAuthLevel( $this->object->session->userdata('schoolcode'), $this->object->session->userdata('username') );
			$query_str = "SELECT authlevel FROM users WHERE user_id='".$this->object->session->userdata('user_id')."' LIMIT 1";
			$query = $this->object->db->query($query_str);
			if($query->num_rows() == 1){
				$row = $query->row();
				$level = $row->authlevel;
			} else {
				return false;
			}
		}
		if( !( $allowed & $level )  ){
			return false ;
		} else {
			return true ;
		}
	}
	
	
	
	
	function GetAuthLevel($user_id = NULL){
		if($user_id == NULL){ $user_id = $this->object->session->userdata('user_id'); }
		$query_str = "SELECT authlevel FROM users WHERE user_id='$user_id' LIMIT 1";
		$query = $this->object->db->query($query_str);
		if($query->num_rows() == 1){
			$row = $query->row();
			$level = $row->authlevel;
			return $level;
		} else {
			return false;
		}
	}
	
	
	
	/**
	 * Checks to see if the user is allowed to view the page or not.
	 *
	 * This function relies upon one of/both of allow/deny ACLs being set.
	 *
	 * @param		string	$message		Message displayed if denied access
	 * @param		bool		$ret				TRUE:return bool. FALSE:die on false (denied)
	 * @return	bool								True if allowed. False/die() if denied
	 */
	function check($message = NULL, $ret = false){
		log_message('debug', "Check function URI: ".$this->object->uri->uri_string());
		$session_username = $this->object->session->userdata('username');
		log_message('debug', "Userauth: Check: Session variable 'username': $session_username");
		
		if( $this->object->session->userdata('loggedin') != 'true' ){
			log_message('debug', "Userauth: Check: Username is null or not set");
			redirect('user/login', 'location');
		}
		
		$username = $session_username;
		$allow = false;
		/* Logic:
			User sets denied list only: allow everyone, deny denied_users[]
			User sets allowed list only: deny everyone, allow valid_users[]
			User sets allowed and denied lists: deny denied_users[], allow allowed_users[]
		*/
		if($this->denied_set == true && $this->allowed_set == false){
			
			//	User has set denied list: YES
			//	User has set allowed list: NO
			$allow = true;		// Allow everyone
			if( in_array($username, $this->denied_users) ){ $allow = false; }
			// Deny people in the denied list
		
		} else if( $this->allowed_set == true && $this->denied_set == false){
			
			//	User has set denied list: NO
			//	User has set allowed list: YES
			$allow = false;		// Deny everyone
			if( in_array($username, $this->allowed_users) ){ $allow = true; }
			// Allow people in the allowed list
		
		} else if( $this->allowed_set == true && $this->denied_set == true ) {
			
			//	User has set denied list: YES
			//	User has set allowed list: YES
			if( in_array( $username, $this->denied_users ) ){ $deny = true; }
			// If user is in the deny list, deny=true,allow=false
			if( (!isset($deny) || !$deny) && in_array($username, $this->allowed_users)){ $allow = true; }
			// Only see if the user is in the valid list if he isn't in the deny list					
		
		} else {
			$allow = true;
		}
		if($allow){				// Final check
			return true;		// User is allowed, just carry on
		} else {
			// Access denied!
			log_message('info','Userauth: Access Denied for '.$username.' in: '.get_class($this->object).'.');
			if($ret == true){
				return false;		// Return false for the function
			}
			else if ($ret == false){		// Do an action (function param)
				#exit( ($message) ? $message : $this->acl_denied );
				// Exit script with the message supplied or the default one
				
				show_error( ($message) ? $message : $this->acl_denied );
				// Show a CI error msg
			}
		}
	}




	function get_allowed($sep = ' '){	return implode($sep, $this->allowed_users); }
	function get_denied($sep = ' '){ return implode($sep, $this->denied_users); }




	/**
	 * Put users into ALLOW ACL
	 *
	 * Calls the function set_allowdeny - shared code for allow/deny functions.
	 *
	 * @param		string		$allow		Space-separated list of usernames/groupnames
	 */
	function set_allow( $allow ){
		$this->set_allowdeny( $allow, $this->allowed_users );
		$this->allowed_set = true;
	}




	/**
	 * Put users into DENY ACL
	 *
	 * Calls the function set_allowdeny - shared code for allow/deny functions.
	 *
	 * @param		string		$deny		Space-separated list of usernames/groupnames
	 */
	function set_deny( $deny ){
		$this->set_allowdeny( $deny, $this->denied_users );
		$this->denied_set = true;
	}




	/**
	 * Put users into appropriate ACL. Is called via set_allow()/set_deny()
	 *
	 * @param		string			$str		Space-separated list of usernames/groupnames
	 * @param		array_ptr		$acl		Pointer to the array to update
	 */
	function set_allowdeny( $str, &$acl ){
		$arr = explode(' ', $str);													// Split string by spaces
		foreach($arr as $item){
			$group = $this->isGroup($item);										// Check to see if this item is a group or a user
			if($group != false){															// It's a group!
				$users = $this->UsersInGroup($group);						// Loop this group to get it's users
				foreach($users as $user){ $acl[] = $user; }			// Add each user in the group to the valid_users list
			} else {
				$acl[] = $item;																	// Add user to the list as this item isn't a group
			}
		}
	}




	/**
	 * Check to see if the supplied acl item is a group or not
	 *
	 * If the item begins with an @ symbol, then the item is a group (UNIX style)
	 *
	 * @param			string				$name		Item you are checking
	 * @return		string/bool						If the item is a group, the name (
	 *																	without the @) is returned, 
	 *																	otherwise the return value is false
	*/
	function isGroup( $name ){
		if($name{0} == '@'){ return substr($name, 1); } else { return false; }
	}




	/**
	 * List all users or all groups depending on parameter
	 *
	 * @param			string		$option		Can be one of:
	 *																'users', 'groups'
	 * @return		array								Array containing list of users/groups
	 */
	function list_ug( $option ){
		switch($option){
			case 'users':
				$sql = 'SELECT username, email, fullname, lastlogin, enabled FROM users';
				$query = $this->object->db->query($sql);
				$result = $query->result_array();
				$arr = $result;
			break;
			case 'groups':
				$sql = 'SELECT groupname, description FROM ci_groups';
				$query = $this->object->db->query($sql);
				$result = $query->result_array();
				/*foreach($result as $a=>$b)
				{
					foreach($b as $c)
					{
						$arr[] = $c;
					}
				}*/
				$arr = $result;
			break;
		}
		return $arr;
	}




	/**
	 * Get a list of the groups that the supplied username belongs to
	 *
	 * @param			array		$username		Username to find the groups he belongs to
	 * @return		array								Group names the specified user belongs to
	 */
	function GroupsOfUser( $username ){
		$sql =	 "SELECT ci_groups.groupname " 
						."FROM usersgroups " 
						."LEFT JOIN groups ON usersgroups.groupid=groups.groupid "
						."LEFT JOIN users ON usersgroups.userid=users.userid "
						."WHERE users.username='$username'";
		$query = $this->object->db->query($sql);
		$result = $query->result_array();
		$groups = array();
		
		if($result){
			foreach($result as $group){
				$groups[] = $group['groupname'];
			}
		}
		if(count($groups) == 0){
			$groups[] = 'None';
		}
		
		return $groups;
	}




	/**
	 * Returns an array of users belonging to specified group
	 *
	 * @param			array		$groupname		Name of group you want
	 * @return		array									Users belonging to the group specified
	 */
	function UsersInGroup( $groupname ){
		$sql =	 "SELECT users.username, users.userid "
						."FROM usersgroups "
						."LEFT JOIN groups ON usersgroups.groupid = groups.groupid "
						."LEFT JOIN users ON usersgroups.userid = users.userid "
						."WHERE ci_groups.groupname = '$groupname'";
		$query = $this->object->db->query($sql);
		$result = $query->result_array();
		$users = array();
		if($result){
			foreach($result as $user){
				$users[] = $user['username'];
			}
		}
		return $users;
	}




	/**
	 * Checks to see if the supplied user exists in the DB
	 *
	 * @param			string		$username		Username to look up
	 * @return		bool									True if user exists
	 */
	function user_exists( $username ){
		$sql = "SELECT userid FROM users WHERE username='$username'";
		$query = $this->object->db->query($sql);
		$c = $query->num_rows();
		$row = $query->row();
		return ($c == 1) ? true : false;
	}




	/**
	 * Add a user to the DB
	 *
	 * @param			array		$userarray		Array containing the user attributes
	 * @return		int										0:Not added,1:User added,2:Already exists
	 */
	function adduser( $userarray ){
		if( ! is_array( $userarray ) ){ return 0; }

		// Only add user if he doesn't already exist
		if( !$this->user_exists( $userarray['username'] ) ){
			// Get only fields we want from the array
			$data['username'] = $userarray['username'];
			$data['fullname'] = $userarray['fullname'];
			$data['password'] = $userarray['password'];
			$data['email'] = $userarray['email'];
			$data['enabled'] = $userarray['enabled'];

			// If password length is less than 40 chars (not SHA1) then SHA1() it
			if( strlen( $data['password'] ) < 40 ){ $data['password'] = sha1( $data['password'] ); }
			
			$this->object->db->insert('users', $data);

			if( count( $userarray['groups'] ) == 1 ){
				// A single group means that users can only belong ot one group
				$this->putuseringroup( $userarray['username'], $userarray['groups'] );
			}
			
			#addusertogroup( $username, $userarray['groups'] );
			return 1;		// User added
		} else {
			return 2;		// User already exists
		}
	}




	function edituser( $userid, $userarray ){
		if( !is_array( $userarray ) ){ return 0; }
		
		// Get only fields we want from the array
		$data['username'] = $userarray['username'];
		$data['fullname'] = $userarray['fullname'];
		$data['password'] = $userarray['password'];
		$data['email'] = $userarray['email'];
		$data['enabled'] = $userarray['enabled'];

		// If password length is less than 40 chars (not SHA1) then SHA1() it
		if( strlen( $data['password'] ) < 40 ){ $data['password'] = sha1( $data['password'] ); }

		$this->object->db->where('userid', $userid);
		$this->object->db->update('users', $data);
		
		#echo $userarray['groups'];
		if( count( $userarray['groups'] ) == 1 ){
			// A single group means that users can only belong ot one group
			$this->putuseringroup( $userarray['username'], $userarray['groups'] );
		}

	}




	/**
	 * Remove a user
	 *
	 * Note: function also removes the user from all groups they are a member of
	 *
	 * @param		string		$username		Username of the user to remove
	 * @return	bool
	 */
	function deleteuser( $username ){
		if( $username == $this->object->session->userdata('username') )
		{
			// Exit if delete object is same as session user (same person)
			log_message('info', 'User change: User '.$username.' tried to delete themself.');
			show_error('You can not delete yourself!');
			exit();
		}
		if( $this->user_exists( $username ) )
		{
			// User exists

			// Delete group
			$sql =	"DELETE FROM usersgroups WHERE userid='".$this->getuserid($username)."'";
			$del_ci_usersgroups = $this->object->db->query($sql);
			
			// Delete user
			$sql = 	"DELETE FROM users WHERE username='$username' LIMIT 1";
			$del_ci_users = $this->object->db->query($sql);
			
			return true;
		} else {
			// User didn't exist in the first place!
			return false;
		}
	}




	/**
	 * Check if account is enabled or not
	 *
	 * @param		string		$user		Single username
	 * @return	bool							User is enabled:true
	 */
	function enabled( $username ){
		$sql = "SELECT enabled FROM users WHERE username='$username'";
		$query = $this->object->db->query($sql);
		$row = $query->row();
		$ret = ($row->enabled == 1) ? true : false;
		return $ret;
	}




	function loggedin(){
		/* To check if user is logged in ...
			> Take the session userdata that will have been set at logon (including a hash)
			> Get required fields from database
			> Make the hash from the DB data and session the same way it was made at logon
			> Compare hash in session with the new one
			> If user is logged in, they will match
		*/
		
		$session_username = $this->object->session->userdata('username');
		$session_bool = $this->object->session->userdata('loggedin');
		$session_schoolcode = $this->object->session->userdata('schoolcode');
		$this->object->db->select(
															'users.username,'
															.'users.lastlogin,'
															.'users.authlevel,'
															//.'school.school_id,'
															/*.'school.code AS schoolcode,'*/
															);
		$this->object->db->from('users');
		//$this->object->db->join('school', 'school.school_id = users.school_id');
		// $this->object->db->where('schools.code', $session_schoolcode);
		$this->object->db->where('users.username', $session_username);
		$this->object->db->limit(1);
		$query = $this->object->db->get();
		log_message('debug', 'loggedin() query: '.$this->object->db->last_query() );
		if( $query->num_rows() == 1){
			log_message('debug', 'loggedin() result: 1 row returned');
			$row = $query->row();
			$lastlogin = $row->lastlogin;
			$authlevel = $row->authlevel;
		} else {
			return false;
		}
		//die("{$lastlogin}||{$session_username}||{$authlevel}");
		//$str = 'c0d31gn1t3r'.$lastlogin.$session_username.$session_schoolcode.$authlevel;
		$str = 'c0d31gn1t3r'.$lastlogin.$session_username;
		log_message('debug', "{$str}");
		//die($str);
		log_message('debug', 'loggedin() hash string: '.$str);
		$hash = sha1($str);
		log_message('debug', 'isloggedin() hash: '.$hash);
		//die("{$hash} == {$this->object->session->userdata('hash')}");
		if( $hash == $this->object->session->userdata('hash') ){
			//die("OK");
		/*if( ( isset($session_username) && $session_username != '') && ( isset($session_bool) && $session_bool == 'true' ) ){*/
			return true;
		} else {
			//die("BADS");
			return false;
		}
	}




	function getuserid($username){
		$sql = "SELECT userid FROM users WHERE username='$username'";
		$query = $this->object->db->query($sql);
		$row = $query->row();
		return $row->userid;
	}
	
	
	
	
	function getusername($userid){
		$sql = "SELECT username FROM users WHERE userid='$userid'";
		$query = $this->object->db->query($sql);
		$row = $query->row();
		return $row->userid;
	}




	function getgroupid($groupname){
		$sql = "SELECT groupid FROM ci_groups WHERE groupname='$groupname'";
		$query = $this->object->db->query($sql);
		$row = $query->row();
		return $row->groupid;
	}




	function getgroupname($groupid){
		$sql = "SELECT groupname FROM ci_groups WHERE groupid='$groupid'";
		$query = $this->object->db->query($sql);
		$row = $query->row();
		return $row->groupname;
	}




	/**
	 * Add user(s) to group(s)
	 *
	 * Note: If both users and groups are supplied, each user is added to each 
	 * group, they are not matched by array keys user1=group1, user2=group2 etc.
	 *
	 * @param		string/array		$users		List of or single username
	 * @param		string/array		$groups		List of or single group name
	 */
	function add_user_to_group( $users, $groups ){
		// If a string is supplied (one user/group) - create an array of it
		if( !is_array( $users ) ){ $users = array( $users ); }
		if( !is_array( $groups ) ){ $groups = array( $groups ); }
	}
	
	
	
	/**
	 * Function to put a user in an exclusive group (no belonging to multiple groups)
	 */	 	
	function putuseringroup( $username, $groupname ){
		$userid = $this->getuserid( $username );
		$groupid = $this->getgroupid( $groupname );
		// Remove user form all groups first
		$sql = "DELETE FROM usersgroups WHERE userid='$userid'";
		$query = $this->object->db->query($sql);
		// Add user to group
		$sql = "INSERT INTO usersgroups (groupid,userid) VALUES ('$groupid','$userid')";
		$query = $this->object->db->query($sql);
	}
	
	
	
	
	
	function GetLastLogin($schoolcode, $username){
		$this->object->db->select(
															'users.username,'
															.'users.lastlogin,'
															.'schools.school_id,'
															.'schools.code AS schoolcode,'
															);
		$this->object->db->from('users');
		$this->object->db->join('schools', 'schools.school_id = users.school_id');
		$this->object->db->where('schools.code', $schoolcode);
		$this->object->db->where('ci_users.username', $username);
		$this->object->db->limit(1);
		$query = $this->object->db->get();
		if( $query->num_rows() > 0){
			$row = $query->row();
			return $row->lastlogin;
		}
	}



}
