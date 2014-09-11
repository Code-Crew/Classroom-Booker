<?php echo $this->session->flashdata('auth') ?>

<?php
$t = 1;
echo form_open('login/assign_submit', array('id'=>'login','class'=>'cssform'), array('page' => $this->uri->uri_string()) );
?>


<fieldset style="width:336px;"><legend accesskey="L" tabindex="<?php echo $t; ?>">Login</legend>
	<input type="radio" name="origin" value="new" onclick="document.getElementById('assign_fields').style.display = 'none';" selected>New User<br>
	<input type="radio" name="origin" value="old" onclick="document.getElementById('assign_fields').style.display = 'block';">Existing User
	<div  id="assign_fields" style="display:none;">
	<p>
	  <label for="username" class="required">Local Username</label>
	  <?php
		$username = @field($this->validation->username);
		echo form_input(array(
			'name' => 'username',
			'id' => 'username',
			'size' => '20',
			'maxlength' => '20',
			'tabindex' => $t,
			'value' => '',
		));
		$t++;
		?>
	</p>
	<?php echo @field($this->validation->username_error); ?>


	<p>
	  <label for="password" class="required">Password</label>
	  <?php
		$password = @field($this->validation->password);
		echo form_password(array(
			'name' => 'password',
			'id' => 'password',
			'size' => '20',
			'tabindex' => $t,
			'maxlength' => '20',
		));
		$t++;
		?>
	</p>
	</div>
	<?php echo @field($this->validation->password_error); ?>
</fieldset>



<?php
$submit['submit'] = array('Login', $t);
$submit['cancel'] = array('Cancel', $t+1, '');
$this->load->view('partials/submit', $submit);
echo form_close();
?>
