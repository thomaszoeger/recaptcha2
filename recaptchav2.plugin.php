<?php

/**
 * Adds a reCAPTCHA to comment forms for visitors that are not logged in
 * and do not have previously approved comments.
 *
 * This version should be able to handle http and https pages with recaptcha
 **/
class RecaptchaV2 extends Plugin
{
    const SITE_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';
    const KEY_MAX_LENGTH = 40;

    private $ready = false;
    private $options;

    /*
     * Configuration settings to appear on the plugin page.
     *
     * @return object FormUI object
     */
    public function configure()
    {
        $ui = new FormUI('recaptchaV2_configuration');
        $ui->append(
            'static',
            'recaptchaV2_info',
            '<p>In order to use reCAPTCHA V2 you need to supply a key pair. You can '
            .'<a href="//code.google.com/apis/recaptcha/" target="_blank">get one for free</a>. '
            .'Please enter your public and private keys below:</p>'
        );

        $public = $ui->append('text', 'public_key', 'recaptchaV2__public_key', 'Public key');
        $public->add_validator('RecaptchaV2::check_keys');
        $public->size = $public->maxlength = self::KEY_MAX_LENGTH;

        $private = $ui->append('text', 'private_key', 'recaptchaV2__private_key', 'Private key');
        $private->add_validator('RecaptchaV2::check_keys');
        $private->size = $private->maxlength = self::KEY_MAX_LENGTH;

        $ui->append('submit', 'save', 'Save');

        return $ui;
    }

    /*
     * Do a basic sanity check on API keys
     *
     * @return array Empty if the key passed, otherwise containing an error string
     */
    static function check_keys($text, $control, $form)
    {
        return (strlen(trim($text)) == self::KEY_MAX_LENGTH)
            ? []
            : [
                'The key you supplied does not appear to be valid. Please check that it is exactly '
                .self::KEY_MAX_LENGTH.' characters long and contains no spaces.'
            ];
    }

    /*
     * Runs when a comment is submitted. Decides whether a CAPTCHA is required
     * and displays on if it is.
     */
    function action_form_comment($form)
    {
        $user = User::identify();
        if ($user->loggedin) {
            return;
        }

        $this->load_options();
        if (!$this->ready) {
            return;
        }

        // If the commenter has been approved as valid before, don't show the captcha
        if (isset($_SESSION['recaptchaV2_commenter_validated'])
            && $_SESSION['recaptchaV2_commenter_validated'] == true) {
            $form->insert('cf_submit', 'static', 'recaptcha', '');
        } // If the commenter has been checked and not approved, show the captcha and add validation
        else if (isset($_SESSION['recaptchaV2_commenter_validated'])) {
            $html
                = '<script>
               window.onload = function() {                   
                   document.getElementById("cf_submit").style.display="none";
                   document.getElementById("g-recaptcha").style.display="block";
               }
		       function YourOnSubmitFn(token) {
		         document.getElementById("comment-public").submit();
		       }
		    </script>';
            $html
                .= '<button class="g-recaptcha" id="g-recaptcha" data-sitekey="'.$this->options['public_key'].'"
				data-callback="YourOnSubmitFn" style="display: none">Senden</button>';

            $recaptcha = $form->insert('cf_submit', 'static', 'recaptcha', $html);
            $recaptcha->add_validator([$this, 'validate']);
        } // If the commenter has not yet been checked, don't show the captcha, but add validation for the commenter
        else {
            $form->cf_commenter->add_validator([$this, 'validate_commenter']);
            $form->insert('cf_submit', 'static', 'recaptcha', '');
        }
    }

    /*
     * Checks if the commenter has been approved before with this name-mail-url-combination.
     */
    function validate_commenter($value, $control, $form)
    {
        if (Comments::get(
            ['email' => $form->cf_email, 'name' => $value, 'url' => $form->cf_url, 'status' => Comment::STATUS_APPROVED]
        )->count) {
            $_SESSION['recaptchaV2_commenter_validated'] = true;

            return [];
        } else {
            $_SESSION['recaptchaV2_commenter_validated'] = false;

            return [
                _t(
                    "You have not been approved before and have to enter a Captcha. If you commented before, you '.
                    'will not have to enter a Captcha if you use the same combination of name, mail and URL.",
                    __CLASS__
                )
            ];
        }
    }

    /*
     * Validate the CAPTCHA
     *
     * @return array Empty if the CAPTCHA was passed, otherwise containing an error string
     */
    function validate($text, $control, $form)
    {    // note, $text will be null

        $resp = isset($_POST['g-recaptcha-response']) ? $_POST['g-recaptcha-response'] : false;

        if (!$resp) {
            $result = ['false', 'incorrect-captcha-sol'];
        }        // discard spam submissions upfront
        else {
            $result = RecaptchaV2::recaptchaV2_post(
                [
                    'secret'   => $this->options['private_key'],
                    'response' => $resp,
                    'remoteip' => $_SERVER['REMOTE_ADDR']
                ]
            );
        }

        // if the first part isn't true then return the second part
        return (trim($result['success']) == true)
            ? []
            : [
                'You did not complete the reCAPTCHA V2 correctly ('.$result['error-codes'][0].')'
            ];
    }

    /*
     * Helper function to send a verification request to teh reCAPTCHA servers
     *
     * @return array
     */
    static function recaptchaV2_post($data)
    {

        $params = http_build_query($data);

        // create curl based post request
        $handle = curl_init(self::SITE_VERIFY_URL);
        $options = [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $params,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/x-www-form-urlencoded'
            ],
            CURLINFO_HEADER_OUT    => false,
            CURLOPT_HEADER         => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true
        ];
        curl_setopt_array($handle, $options);
        $response = curl_exec($handle);
        curl_close($handle);
        // decode response
        $_result = json_decode($response, true);

        // check
        return ($_result);
    }

    function action_plugin_activation($file)
    {
        if (Plugins::id_from_file($file) == Plugins::id_from_file(__FILE__)) {
            Options::set_group('recaptchaV2', ['public_key' => '', 'private_key' => '']);
        }
    }

    function action_plugin_deactivation($file)
    {
        if (Plugins::id_from_file($file) == Plugins::id_from_file(__FILE__)) {
            Options::delete_group('recaptchaV2');
        }
    }

    /*
     * Display a notice in the admin screen if the plugin is installed but
     * API keys need to be supplied
     *
     * @return array Empty if the key passed, otherwise containing an error string
     */
    function action_admin_info()
    {
        $this->load_options();
        if (!$this->ready) {
            echo '<div class="container">The reCAPTCHA V2 plugin is almost ready to go. Please go the the '
                .'plugin configuration section to enter your API keys.</div>';
        }
    }

    private function load_options()
    {
        $this->options = Options::get_group('recaptchaV2');
        $this->ready = (empty($this->options['public_key']) || empty($this->options['private_key'])) ? false : true;
    }
}

?>