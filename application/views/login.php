<!doctype html>
<html lang="en">
	<head>
    	<title>PubQuiz</title>
        <link href="/css/bootstrap.min.css" rel="stylesheet" type="text/css" />
        <link href="/css/bootstrap-responsive.min.css" type="text/css" rel="stylesheet"/>
        <script src="/js/jquery-1.7.2.min.js"></script>
        <script src="/js/bootstrap.min.js"></script>
        <script src="/js/bootstrap-tab.js"></script>
        <script src="/js/bootstrap-dropdown.js"></script>
        <script src="/js/bootstrap-collapse.js"></script>
        <script src="/js/bootstrap-transition.js"></script>
        <script src="/js/bootstrap-alert.js"></script>
	</head>
    <body>
    <div class="navbar navbar-fixed-top">
                <div class="navbar-inner">
                    <div class="container">
                        <ul class="nav">
                            <li>
                                <a class="brand" href="#">PubQuiz</a>
                            </li>
                            <li class="dropdown">
                                <a class="dropdown-toggle" data-toggle="dropdown">Account <b class="caret"></b></a>
                                <ul class="dropdown-menu">
                                    <li><a href="#"><i class="icon-user"></i> Login / Register</a></li><!-- Only visible if logged out -->
                                    <li><a href="#"><i class="icon-off"></i> Logout</a></li><!-- Only visible if logged in -->
                                </ul>
                            </li>
                            <li class="dropdown">
                            	<a class="dropdown-toggle" data-toggle="dropdown" href="#">Manage <b class="caret"></b></a>
                                <ul class="dropdown-menu">
                                	<li class="nav-header">Quiz</li>
                                	<li class="divider"></li>
                               		<li><a href="#"><i class="icon-pencil"></i> New Quiz</a></li>
                                    <li><a href="#"><i class="icon-pencil"></i> Manage Quiz'</a></li>
                                </ul>
                            </li>
                        </ul>
                    </div>
                </div>
            </div> <hr /><hr />
            <div class="container">
                <div class="hero-unit">
                   <h2>PubQuiz Login</h2>
                </div>
                <div class="span1 offset3">&nbsp;
                </div>
                <div class="span4">
                <form>
                   		<div class="control-group">
                        	<label class="control-label" for="inputIcon"><strong>Email Address</strong></label>
                            <div class="controls">
                            	<div class="input-prepend">
                                	<span class="add-on">
                                    	<i class="icon-envelope"></i>
                                    </span><input class="span4" style="width: 330px;" id="inputIcon" type="email" />
                                    
                                </div>
                            </div>
                            <label class="control-label" for="inputIcon2"><strong>Password</strong></label>
                            <div class="controls">
                            	<div class="input-prepend">
                                	<span class="add-on">
                                    	<i class="icon-asterisk"></i>
                                    </span><input class="span4" style="width: 330px;"id="inputIcon2" type="password" />
                                </div>
                            </div>
                            <div class="pull-right">
                            	<button class="btn btn-primary">Login</button>
                            </div>
                        </div>
                   </form>
                </div>
                
            </div>
          </body>
            <script>
				$('.dropdown-toggle').dropdown();
            </script>
    </body>
</html>