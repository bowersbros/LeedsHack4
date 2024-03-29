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
                   <h2>New Question</h2>
                </div>
                <div class="row" style="min-height: 185px;">
                	<div class="span11 well" style="min-height: 185px;">
                    	<form action="#" method="post" id="questions">
                        <div class="questionarea">
                        <h3>Enter Question <span>1's</span> text</h3><hr />
                        	<input type="text" name="questionText[]" class="countChars" rel="question" placeholder="Enter question here.." style="margin: 0 auto; width:1060px;" maxlength="160"/>
                            <p class="pull-right"><span class="questionCharsLeft">160</span> Characters Left</p><br /><br />
                        <h3>Enter Question <span>1's</span> Answer</h3><hr />
                        	<input type="text" name="questionAnswer[]" class="countChars" rel="answer" placeholder="Enter answer here.." style="margin: 0 auto; width:1060px;" maxlength="160"/>
                            <p class="pull-right"><span class="answerCharsLeft">160</span> Characters Left</p><br />
                            <hr />
                           </div>
                           
                        </form>
                        <p><span><a href="#" class="clone">More Questions</a></span><span class="pull-right"><button id="SubmitButton" class="btn btn-primary">Submit</button></span></p>
                    </div>
                </div>
            </div>
          </body>
            <script>
				$('#SubmitButton').click(function(){
					$('#questions').submit();
				});
				$('.dropdown-toggle').dropdown();
				$('.countChars').keyup(function(){
					var attr = $(this).attr('rel');
					var length = $(this).val().length;
					var total = 160 - length;
					$('.' + attr + 'CharsLeft').html(total);
				});
				var counter = 1
				$('.clone').click(function(e){
					
					e.preventDefault();
					$('.questionarea').clone().attr('class','random').appendTo('#questions').css('margin-top','15px');
					counter = counter + 1;
					$('.random:last h3 span').html(counter + "'s");
				});
            </script>
    </body>
</html>
