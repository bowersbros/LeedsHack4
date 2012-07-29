<?php
abstract class Password {
	private function __construct() {
		
	}
	
	final static private function createPasswordSalt($length = 16) {
		$salt = '';
		while(strlen($salt) < $length) {
			$salt .= dechex(mt_rand());
		}
		return substr($salt, 0, $length);
	}
	final static public function createPasswordHash($password, $salt = null) {
		$salt or $salt = self::createPasswordSalt();
		$count = pow(2, 10);
		do {
			$hash = $salt . (hash_hmac('whirlpool', $salt . $password, $salt . AUTH_SALT));
		}
		while (--$count);
		return $hash;
	}
	final static public function comparePassword($password, $hash) {
		return $hash == self::createPasswordHash($password, substr($hash, 0, 16), 10);
	}
}

class Auth extends CI_Controller {
	public $data = array();
	/*	
	 *	Constructer Method
	*/	
	public function __construct() {
		parent::__construct();
	}
	public function dashboard() {
		$this->load->view('dashboard');

	}
	public function index() {
 if( $this->session->userdata('session_id') ) print "yes the session has been set";
else print "no the session hasn't been set";  		
		
		$data = array();	//	reset all the vars
		
		if($this->input->post('process') && $this->input->post('process') == 'login') {	//	login
			$this->process_login();
		} else if($this->input->post('process') && $this->input->post('process') == 'register') { //	register
			$this->process_register();
		} else {
			$this->load->view('register');
		}
	}
	
	/*	
	 *	Process the login - normal login
	*/	
	public function process_login() {
		$data = array();			//	reset all the vars
		$q = $this->db->query("SELECT * FROM quizmaster WHERE email = ? AND password = ?;",array($this->input->post('email'),$this->input->post('password'))); 
		echo $q->num_rows();
		exit;
		
		if($q->num_rows() > 0) {
			foreach($q->result() as $row) {
				$user_id = $row->id;
			}
		} else {
			$data['error'] = 'Invalid username or password.';
			return $this->load->view('index', $data);	
		}
		
		$user_data = array('logged_in'=>true);
		$this->session->set_userdata($user_data);
		header('Location: /auth/dashboard');
		exit;
	}
	
	public function process_register(){
		$data = array();
		$q = $this->db->query("INSERT INTO quizmaster SET `email` = ?,`password` = ?;",array($this->input->post('email'),Password::createPasswordHash($this->input->post('password'))));
		// make database field for email unique
		if($q){
			$user_data = array('logged_in'=>true);
			$this->session->set_userdata($user_data);
			header('Location: /auth/dashboard');
			exit;
		} else {
			$data['error'] = 'Email address already in use.';
			return $this->load->view('index',$data);
		}
	}
}