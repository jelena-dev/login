<?php 
/****** Helper functions ******/
function clean($string)
{
    return htmlentities($string);
}

function redirect($location)
{
    return header("Location: {$location}");
}

function set_message($message)
{
    if(!empty($message))
    {
        $_SESSION['message']=$message;
    }
    else
    {
        $message="";
    }
}

function display_message()
{
    if(isset($_SESSION['message']))
    {
        echo $_SESSION['message'];
        unset($_SESSION['message']);
    }
}

function token_generator()
{
    $token=$_SESSION['token']=md5(uniqid(mt_rand(), true));
    return $token;
}

function validation_errors($error_message)//ne radi
{
    
$message = <<<DELIMITER

<div class="alert alert-danger alert-dismissible" role="alert">
  	<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
  	<strong>Warning!</strong> $error_message
 </div>
DELIMITER;

return $error_message;

}


function email_exists($email)
{
    $sql="SELECT id FROM users WHERE email='$email'";
    $result=query($sql);
    if(row_count($result)==1)
    {
        return true;
    }
    else
    {
        return false;
    }
}

function username_exists($username)
{
    $sql="SELECT id FROM users WHERE username='$username'";
    $result=query($sql);
    if((row_count($result))==1)
    {
        return true;
    }
    else
    {
        return false;
    }
}


function send_email($email,$subject,$msg,$headers)
{
    return mail($email,$subject,$msg,$headers);

}

/****** Validation functions ******/

function validate_user_registration()
{
    $errors=[];
    $min=3;
    $max=20;

    if($_SERVER['REQUEST_METHOD']=="POST")
    {
        $first_name         =clean($_POST['first_name']);
        $last_name          =clean($_POST['last_name']);
        $username           =clean($_POST['username']);
        $email              =clean($_POST['email']);
        $password           =clean($_POST['password']);
        $confirm_password   =clean($_POST['confirm_password']);
    
        if(strlen($first_name)<$min)
        {
            $errors[]="First name cannot be less than {$min} letters!!!";
        }
        if(strlen($first_name)>$max)
        {
            $errors[]="First name cannot be more than {$max} letters!!!";
        }



        if(strlen($last_name)<$min)
        {
            $errors[]="Last name cannot be less than {$min} letters!!!";
        }
        if(strlen($last_name)>$max)
        {
            $errors[]="Last name cannot be more than {$max} letters!!!";
        }



        if(strlen($username)<$min)
        {
            $errors[]="Username cannot be less than {$min} letters!!!";
        }
        if(strlen($username)>$max)
        {
            $errors[]="Username cannot be more than {$max} letters!!!";
        }
        if(username_exists($username))
        {
            $errors[]="Username exists!";
        }



        if(email_exists($email))
        {
            $errors[]="Email exists!";
        }
        if(strlen($email)<$min)
        {
            $errors[]="Email cannot be less than {$min} letters!!!";
        }


        if($password !== $confirm_password)
        {
            $errors[]="Password and Cofirm password aren't same!!!";
        }



        if(!empty($errors))
        {
            foreach($errors as $error)
            {
                echo validation_errors($error);
            }
        }
        else
        {
            if(register_user($first_name, $last_name, $username, $email, $password))
            {
                set_message("<p class='bg-success text-center'>Please check your email!</p>");
                redirect("index.php");
            }
        }


        
    
    }
}

/****** Register user functions ******/

function register_user($first_name, $last_name, $username, $email, $password)
{
    $first_name     = escape($first_name);
    $last_name      = escape($last_name);
    $username       = escape($username);
    $email          = escape($email);
    $password       = escape($password);

    if(email_exists($email))
    {
        return false;
    }
    else if (username_exists($username))
    {
        return false;
    }
    else
    {
        $password=md5($password);
        $validation_code=md5($username+microtime());

        $sql="INSERT INTO users(first_name, last_name, username,email, password, validation_code,active )";
        $sql.=" VALUES('$first_name','$last_name','$username','$email','$password','$validation_code','0')";
        $result=query($sql);
        confirm($result);


        $subject="Activate Account";
        $msg="Please click the link below to activate
        login/activate.php?email=$email&code=$validation_code";
        
        $header="From: noreply@youtwebsite.com";
        send_email($email,$subject,$msg,$headers);
        return true;
    }

}

/****** Activate user functions ******/

function activate_user()
{
    if($_SERVER['REQUEST_METHOD']=="GET")
    {

    if(isset($_GET['email']))
    {
        $email=clean($_GET['email']);
        $validation_code=clean($_GET['code']);

        $sql="SELECT id FROM users WHERE email='".escape($_GET['email'])."' AND validation_code='".escape($_GET['code'])."'";
        $result=query($sql);
        confirm($result);

        if(row_coun($result)==1)
        {
           $sql2="UPDATE users SET active=1,validation_code=0 WHERE email='".escape($_GET['email'])."' AND validation_code='".escape($_GET['code'])."' ";
           $result2=query($sql2);
           confirm($result2);


            set_message("<p class='bg-success'>Your account has been activated pleas login</p>");
            redirect("login.php");
        }
        
    }
}
    
}

/****** Validation login  functions ******/

function validate_user_login()
{
  
    $errors=[];
    $min=3;
    $max=20;


    if($_SERVER['REQUEST_METHOD']=="POST")
    {
        $email              =clean($_POST['email']);
        $password           =clean($_POST['password']);
        $remember           =isset($_POST['remember']);

        if(empty($email))
        {
            $errors[]="Please fill in the blanke";
        }

        if(empty($password))
        {
            $errors[]="Please fill in the blanke";
        }

        if(!empty($errors))
        {
            foreach($errors as $error)
            {
                echo validation_errors($error);
            }
        }

        

        else
        {
            if(login_user($email,$password,$remember))
            {
                redirect('admin.php');
            }
            else
            {
                echo validation_errors("smth is not ok");
            }
        }
    }


}

/****** Validation functions ******/

function login_user($email,$password,$remember)
{
    $sql="SELECT password,id FROM users WHERE email='".escape($email)."' AND active=1";
    $result=query($sql);
    if(row_count($result)==1)
    {
        $row=fetch_array($result);
        $db_password=$row['password'];

        if(md5($password)===$db_password)
        {
            if($remember=="on")
            {
                setcookie('email',$email,time()+ 86400);
            }
            $_SESSION['email']=$email;
            // kada zelimo da ostanemo ulogovani
            return true;

        }
        else
        {
            return false;
        }
    }

}

/****** logged in  functions ******/
function logged_in()  //kada zelimo da ostanemo ulogovani
{
    if(isset($_SESSION['email']) OR isset($_COOKIE['email']))
    {
        return true;
    }
    else
    {
        return false;
    }
}
/****** Recover Password functions ******/
function recover_password()
{
    if($_SERVER['REQUEST_METHOD']=="POST")
    {
      if(isset($_SESSION['token']) && $_POST['token']===$_SESSION['token'])
      {
        $email=clean($_POST['email']);
        if(email_exists($email))
        {
            
            $validation_code=md5($email+ microtime());

            setcookie('temp_access_code', $validation_code, time()+900);

            $sql="UPDATE users SET validation_code='".escape($validation_code)."' WHERE email='".escape($email)."'";
            $result=query($sql);
            confirm($result);
            $subject="Please reset your password";
            $message="Here is your password rest code {$validation_code}
            Click here to reset your password http://localhost/code.php?email=$email&code=$validation_code
            ";
            $headers="From; noreply@yourwebsite.com";
            
            if(!send_email($email,$subject,$message,$headers))
            {
                echo validation_errors("This email does not exist");

            }
            set_message("<p>Check your email</p>");
            redirect("index.php");
        }
        
      }//token
      else
      {
        redirect("index.php");
      }
      if(isset($_POST['cancel_submit']))
      {
          redirect("login.php");
      }
    }//post
}//function

set_message("<p>Check your email</p>");

/****** Recover Password functions ******/

function validate_code()
{
    if(isset($_COOKIE['temp_access_code']))
    {
         if(!isset($_GET['email']) && !isset($_GET['code']))
            {
                redirect("index.php");

            }
            elseif (empty($_GET['email']) OR empty($_GET['code']) )
            {
                redirect("index.php");
            }
            else
            {
                if(isset($_POST['code']))
                {
                    $email=clean($_GET['email']);
                    $validation_code=clean($_POST['code']);
                    $sql="SELECT id FROM users WHERE validation_code='".escape($validation_code)."' AND email= '".escape($email)."'";
                    $result=query($sql);
                   if(row_count($result)==1)
                   {
                    setcookie('temp_access_code', $validation_code, time()+300);
                       redirect("reset.php?email=$email&code=$validation_code");
                   }
                   else
                   {
                    echo validation_errors("Sorry wrong validation code");
                   }
                }
            }
        
    }
    else
    {
        set_message("<p>Your valodation cookie was expired</p>");
        redirect("recover.php");
    }
}

/****** Reset Password functions ******/
function password_reset()
{
    if(isset($_COOKIE['temp_access_code']))//trajanje
    {
        if(isset($_GET['email']) && isset($_GET['code']))
        {
            if(isset($_SESSION['token']) && isset($_POST['token']) && $_POST['token']===$_SESSION['token']) //da svi podaci dolaze iz forme
            {

                if($_POST['password']===$_POST['confirm_password'])
                {
                    $update_password=md5($_POST['password']);
                    $sql="UPDATE users SET password='".escape($update_password)."', validation_code=0 WHERE email='".escape($_GET['email'])."'";
                    $result=query($sql);
                    set_message("<p>password has been update</p>");
                    redirect("login.php");

                }
                else
                {
                    echo validation_errors("Password fields don't match");
                }
                
            }
        }
           

    }
    else
    {
        set_message("<p>Your time is up</p>");
        redirect("recover.php");

    }
}


?>