<?php
class Weeks_model extends Model{





	function Weeks_model(){
		parent::Model();
		$this->CI =& get_instance();
  }
  
  
  
  
  
	function Get($week_id = NULL, $school_id = NULL){
		if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		if($week_id == NULL){
			return $this->CI->crud->Get('weeks', NULL, NULL, $school_id);	//, NULL, NULL, NULL, 'name desc');
		} else {
			return $this->CI->crud->Get('weeks', 'week_id', $week_id);
		}
	}
	
	
	
	
	
	/**
	 * Count the number of weeks for this school ID
	 * 
	 * @param	int	$school_id	ID of school to count the weeks for
	 * @return	int	Number of weeks for this school	 	 	 
	 */
	function WeeksCount($school_id = NULL){
		if( $school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		$query = $this->db->query("SELECT week_id FROM weeks WHERE school_id='$school_id'");
		return $query->num_rows();
	}
  
  
  
  
  
  function Add($data){
  	return $this->CI->crud->Add('weeks', 'week_id', $data);
		/*// Run query to insert blank row
		$this->db->insert('weeks', array('week_id' => NULL) );
		// Get id of inserted record
		$week_id = $this->db->insert_id();
		// Now call the edit function to update the actual data for this new row now we have the ID
		$this->edit($week_id, $data);
		return $week_id;*/
  }
  
  
  
  
  
  function Edit($week_id, $data, $school_id = NULL){
  	return $this->CI->crud->Edit('weeks', 'week_id', $week_id, $data);
  	/*if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		$this->db->where('week_id', $week_id);
		$this->db->set('school_id', $school_id);
		$result = $this->db->update('weeks', $data);
		// Return bool on success
		if( $result ){
			return true;
		} else {
			return false;
		}*/
  }
  
  
  
  
  
  function GetAcademicYear($school_id = NULL){
  	if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
  	$query_get = $this->db->getwhere('academicyears', array('school_id' => $school_id), 1);
		if($query_get->num_rows() == 1){
			// Got it!
			return $query_get->row();
		} else {
			// No results
			return false;
		}
  }
  
  
  
  
  
  function SaveAcademicYear($data, $school_id = NULL){
  	if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
  	$query_get = $this->db->getwhere('academicyears', array('school_id' => $school_id), 1);
		if($query_get->num_rows() == 1){
			// Row already in, updating record
			$this->db->where('school_id', $this->session->userdata('school_id'));
			$result = $this->db->update('academicyears', $data);
		} else {
			// No rows, inserting ...
			$data['school_id'] = $this->session->userdata('school_id');
			$result = $this->db->insert('academicyears', $data);
		}
		return $result;
	}
  
  
  
  
  
	/**
	 * Deletes a week with the given ID
	 *
	 * @param   int   $week_id   ID of week to delete
	 * @param		int		$school_id		School ID	 
	 *
	 */
	function Delete($week_id, $school_id = NULL){
		if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		
		$this->db->where('week_id', $week_id);
		$this->db->where('school_id', $school_id);
		$this->db->delete('weeks');
		
		$this->db->where('week_id', $week_id);
		$this->db->where('school_id', $school_id);
		$this->db->delete('weekdates');
	}
	
	
	
	
	/**
	 * Returns an array of all Monday dates in the acaedmic year
	 * 
	 * @return	array	monday dates
	*/	 	 	 	
	function GetMondays3(){
		// Get academic year dates
		$AcademicYear = $this->GetAcademicYear();
		// Get holidays (use global object as we're calling a function in the Holidays model
		$holidays = $this->CI->M_holidays->Get();	//$this->session->userdata('schoolcode'));
		// Set date format
		$date_format = "Y-m-d";
		#echo "Finding all mondays between {$AcademicYear->date_start} and {$AcademicYear->date_end} ...";
		$ad_date_start = strtotime($AcademicYear->date_start);
		$ad_date_end = strtotime($AcademicYear->date_end);
		$time_between = $ad_date_end - $ad_date_start;
		// Find all the days
		$day_count = ceil($time_between/24/60/60);
		// Find the names/dates of the days
		$newtime = 0;
		for($i=0; $i<=$day_count; $i++){
			if($i==0 && date("l", $newtime) != "Monday"){
				// We're starting in the middle of a week.... show 1 earlier week than the code that follows
		    for($s=0; $s<=5; $s++){
		    #for($s=1; $s<=6; $s++){
		    	$newtime = $ad_date_start - ($s*60*60*24);
		    	if(date("l", $newtime) == "Monday"){
		    		$end_of_week = $newtime + (6*60*60*24);
		    		#echo date($date_format, $newtime)."<br/><br/>";	// through ".date("F jS, Y",$end_of_week)." is a week.<br />";
		    		// Put date into array
		    		$dates[$i]['date'] = date($date_format, $newtime);
		    		// Check to see if this date currently belongs to another week
		    		$dates[$i]['week_id'] = $this->WeekExists($dates[$i]['date']);
		    		// Check to see if this date is in a holiday
		    		$dates[$i]['holiday'] = $this->WeekInHoliday($dates[$i]['date'], $holidays);
		    	}
		    }
		  } else {
		   	$newtime = $ad_date_start + ($i*60*60*24);
		   	if(date("l",$newtime) == "Monday"){
		   		//Beginning of a week... show it
		   		$end_of_week = $newtime+(6*60*60*24);
		   		#echo date("d.m.Y",$newtime)."<br/><br/>";	// through ".date("F jS, Y",$end_of_week)." is a week.<br /><br />";
		    	$dates[$i]['date'] = date($date_format, $newtime);
		    	// Check to see if this date currently belongs to another week
		    	$dates[$i]['week_id'] = $this->WeekExists($dates[$i]['date']);
		    	// Check to see if this date is in a holiday
		    	$dates[$i]['holiday'] = $this->WeekInHoliday($dates[$i]['date'], $holidays);
		   	}
			}
		}
		return $dates;
	}
	
	
	
	
	
	function GetMondays($school_id = NULL, $holidays = NULL){
		if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		// Get academic year dates
		$AcademicYear = $this->GetAcademicYear();
		
		// Get holidays (use global object as we're calling a function in the Holidays model
		/*if($holidays == NULL){
			$holidays = $this->CI->M_holidays->Get();
			if($holidays){
				foreach($holidays as $holiday){
					$hols[$holiday->holiday_id]['start'] = strtotime($holiday->date_start);
					$hols[$holiday->holiday_id]['end'] = strtotime($holiday->date_end);
				}
			} else {
				$hols = false;
			}
		}*/
		
		#print_r($hols);

		
		/*$weeks_query = $this->db->query("SELECT week_id, date FROM weekdates WHERE school_id='$school_id'");
		$results = $weeks_query->result_array();
		foreach($results as $row){
			$weeks[$row['date']] = $row['week_id'];
		}*/
		$weeks = $this->WeekDateIDs($school_id);

		// Set date format
		$date_format = "Y-m-d";
		
		$ay_start = strtotime($AcademicYear->date_start);	//mktime(0,0,0,9,4,2006);
		$ay_end = strtotime($AcademicYear->date_end);	//mktime(0,0,0,7,20,2007);
		
		#echo "Start: $ay_start, End: $ay_end";
		
		$i=0;
		while($ay_start <= $ay_end){
		
			if( date("w", $ay_start) == 1 ){
				$nextdate = date("Y-m-d", $ay_start);
			} else {
				$nextdate = date("Y-m-d", strtotime("last Monday", $ay_start));
			}
			$ay_start = strtotime("+1 week", $ay_start);
			
			#echo "This: $ay_start";
			$dates[$i]['date'] = $nextdate;
			
			if($weeks){
				$dates[$i]['week_id'] = (array_key_exists($nextdate, $weeks)) ? $weeks[$nextdate] : 0;	//$this->WeekExists($nextdate);
			}
			
			#$query_str = "SELECT holiday_id FROM holidays WHERE date_start <= '$nextdate' AND date_end >= '$nextdate' LIMIT 1";
			#$query = $this->db->query($query_str);
			#$found_hol = false;
			$nextdate = strtotime($nextdate);
			
			/*if(isset($hols) && $hols){
				foreach($hols as $hol){
					if( ($hol['start'] <= $nextdate) AND ($hol['end'] >= $nextdate) ){
						$found_hol = true;
					}
				}
				$dates[$i]['holiday'] = $found_hol;	//false;	//($query->num_rows() == 1) ? true : false;
			} else {
				$dates[$i]['holiday'] = false;
			}*/
			
			$i++;
		}	// End while loop
		
		return $dates;
	}
	
	
	
	
	
	function WeekDateIDs($school_id = NULL){
		if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		$weeks_query = $this->db->query("SELECT week_id, date FROM weekdates WHERE school_id='$school_id'");
		$results = $weeks_query->result_array();
		foreach($results as $row){
			$weeks[$row['date']] = $row['week_id'];
		}
		if(isset($weeks)){
			return $weeks;
		} else {
			return false;
		}
	}
	
	
	
	
	
	/**
	 * Checks to see if a given week-commencing date belongs to a given school week
	 * 
	 * @param		date		$date		Date of week to check
	 * @return		int		Week_ID on true, otherwise false
	 */	 	 	 	 	
	function WeekExists($date, $school_id = NULL){
  	if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		$this->db->where('date', $date);
		$this->db->where('school_id', $school_id);
		$this->db->limit('1');
  	$query_get = $this->db->get('weekdates');
		if($query_get->num_rows() == 1){
			// Got it!
			$row = $query_get->row();
			return $row->week_id;
		} else {
			// No results
			return 0;
		}
	}
	
	
	
	
	
	function WeekInHoliday($date, $holidays, $school_id = NULL){
		foreach($holidays as $holiday){
			$hol_date_start = strtotime($holiday->date_start);
			$hol_date_end = strtotime($holiday->date_end);
			$week_date = strtotime($date);
			#echo $date . ": " . $holiday->date_start . "  to  " . $holiday->date_end . "<br><br>";
			if( ($week_date >= $hol_date_start) && ($week_date <= $hol_date_end) ){
				return true;
			} else {
				return false;
			}
		}
	}
	
	
	
	
	
	function UpdateMondays($week_id, $dates, $school_id = NULL){
		if($school_id == NULL){ $school_id = $this->session->userdata('school_id'); }
		
		// First get rid of all current dates for this week
		$this->db->where('week_id', $week_id);
		$this->db->where('school_id', $school_id);
		$this->db->delete('weekdates');
		
		// Database info that stays the same
		$data['week_id'] = $week_id;
		$data['school_id'] = $school_id;
		
		// Loop all dates
		foreach($dates as $date){
		
			// Database array
			$data['date'] = $date;
			
			// Check to see if this date already exists
			$query = $this->db->query("SELECT date FROM weekdates WHERE date='$date' AND school_id='$school_id'");
			$rows = $query->num_rows();
			
			if( $rows == 1){
				// We got one row where the date is another week_id, so change it:
				#$this->db->query("UPDATE weekdates SET week_id='$week_id' WHERE date='$date' AND school_id='$school_id'");
				$where = "date='$date' AND school_id=$school_id";
				$str = $this->db->update_string('weekdates', $data, $where);
			} else {
				$str = $this->db->insert_string('weekdates', $data);
			}
			// Run query
			$this->db->query($str);
			$str = '';
			$where = '';
			
			/*
			$this->db->where('date', $date);
			$update = $this->db->update('weekdates', $data);
			if(!$update){
				$this->db->insert('weekdates', $data);
			}*/
			/*  // Attempt insert
			$insert = $this->db->insert('weekdates', $data);
			// If insert fails, it means the row for the date already exists (but assigned to another week_id)
			if(!$insert){
				// So update it, but change week_id
				$this->db->where('date', $date);
				$update = $this->db->update('weekdates', $data);
			}*/
		}
		
	}
  
  
  
  
  
}
?>
