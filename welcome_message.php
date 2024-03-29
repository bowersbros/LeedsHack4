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
                   <h2>PubQuiz Dashboard</h2>
                </div>
                <div class="row" style="min-height: 185px;">
                	<div class="span3 well" style="min-height: 185px;">
                    	<h3>Stats</h3>
                    	<ul>
                            <li>Current # of Users: 32</li>
                            <li>Current # of Questions: 11</li>
                            <li>Current # of Answers: 17</li>
                    	</ul>
                    </div>
                    <div class="span3 well" style="min-height: 185px;">
                    	<h3>Scoreboard</h3>
                    	<div class="progress progress-success" style="background-image: none; background-color: #ee5f5b;">
                        	<div class="bar" style="width: 60%;">
                            </div>
                        </div>
                        <p>60% Have Answered Correctly.</p>
                    </div>
                    <div class="span4 well" style="min-height: 185px;">
                    	<h3>Current Question</h3>
                        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean eu nunc ac metus luctus feugiat. Nulla aliquam risus ut diam venenatis quis vehicula risus amet.</p>
                        <p>Time Elapsed: </p>
                        <p><a href="#">View All Questions</a> | <a href="#">Next Question &raquo;</a></p>
                    </div>
                </div>
            </div>
          </body>
            <script>
				$('.dropdown-toggle').dropdown();
            </script>
    </body>
</html>