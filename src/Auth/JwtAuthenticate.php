<?php
namespace mrduongnv\JwtAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\Utility\Security;
use Exception;
use JWT;
use Cake\Log\Log;
use Abraham\TwitterOAuth\TwitterOAuth;
// Short classname

/**
 * An authentication adapter for authenticating using JSON Web Tokens.
 *
 * ```
 *  $this->Auth->config('authenticate', [
 *      'mrduongnv/JwtAuth.Jwt' => [
 *          'parameter' => '_token',
 *          'userModel' => 'Users',
 *          'scope' => ['User.active' => 1]
 *          'fields' => [
 *              'id' => 'id'
 *          ],
 *      ]
 *  ]);
 * ```
 *
 * @copyright 2015 mrduongnv
 * @license MIT
 * @see http://jwt.io
 * @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
 */
class JwtAuthenticate extends BaseAuthenticate
{
    /**
     * Constructor.
     *
     * Settings for this object.
     *
     * - `parameter` - The url parameter name of the token. Defaults to `_token`.
     *   First $_SERVER['HTTP_AUTHORIZATION'] is checked for token value.
     *   Its value should be of form "Bearer <token>". If empty this query string
     *   paramater is checked.
     * - `userModel` - The model name of the User, defaults to `Users`.
     * - `fields` - Has key `id` whose value contains primary key field name.
     *   Defaults to ['id' => 'id'].
     * - `scope` - Additional conditions to use when looking up and authenticating
     *   users, i.e. `['Users.is_active' => 1].`
     * - `contain` - Extra models to contain.
     * - `unauthenticatedException` - Fully namespaced exception name. Exception to
     *   throw if authentication fails. Set to false to do nothing.
     *   Defaults to '\Cake\Network\Exception\UnauthorizedException'.
     * - `allowedAlgs` - List of supported verification algorithms.
     *   Defaults to ['HS256']. See API of JWT::decode() for more info.
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry
     *   used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, $config)
    {
        $this->config([
            'parameter' => '_token',
            'fields' => ['id' => 'id'],
            'unauthenticatedException' => '\Cake\Network\Exception\UnauthorizedException',
            'allowedAlgs' => ['HS256']
        ]);

        parent::__construct($registry, $config);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Network\Request $request The request object.
     * @param \Cake\Network\Response $response Response object.
     * @return bool|array User record array or false on failure.
     */
    public function authenticate(Request $request, Response $response)
    {
        return $this->getUser($request);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Network\Request $request Request object.
     * @return bool|array User record array or false on failure.
     */
    public function getUser(Request $request)
    {
        $token = $this->_getToken($request);
        if ($token && (substr($token, 0 , 7) == "Bearer ")){
            return $this->_findUser(substr($token, 7));
        } elseif ($token && (substr($token, 0 , 8) == "FBoAuth ")) {
            return $this->getUserFbInfo(substr($token, 8));
        } elseif ($token && (substr($token, 0 , 8) == "GGoAuth ")) {
            return $this->getUserGgInfo(substr($token, 8));
        } elseif ($token && (substr($token, 0 , 8) == "TWoAuth ")) {
            return $this->getUserTwInfo(substr($token, 8));
        }

        return false;
    }

    // Method get user from twitter oAuth
    protected function getUserTwInfo($token){
        Log::info($token); 
        $tokens = explode('&',$token);
        $access_token = substr($tokens[0],12);
        $access_token_secret = substr($tokens[1],19);
        $isUser = $this->checkAccessToken($access_token);
        if ($isUser != null){ 
            // Nếu token này đã có trong database thì cho login luôn ko cần quan tâm
            return $isUser->toArray();
        } else {
            // Nếu chưa có token trong database thì đây là token mới, get info token này
            // lấy user_id và và email rồi kiểm tra xem đã có trong database chưa nếu chưa
            // thì đăng kí mới user này, nếu có rồi thì cho login và lưu token mới
            define("CONSUMER_KEY", "avKGacnhBv6eMp297cGuDfCzZ");
            define("CONSUMER_SECRET", "2itllQEbCtxgCSqsa098NZIKcLCzjft0rwhjNJzSflnENIxMLa");
            $connection = new TwitterOAuth(CONSUMER_KEY, CONSUMER_SECRET, $access_token, $access_token_secret);
            $content = $connection->get("account/verify_credentials");
            $twInfo = json_decode(json_encode($content), true);
            //tw không trả về email
            $email = (isset($twInfo['email'])) ? $twInfo['email'] : '';
            $user = (isset($twInfo) && array_key_exists('id_str', $twInfo)) ? $this->checkUser('twitter_id',$twInfo['id_str'],$email) : null ;
            
            if ($user != null) {
                $this->saveToken($user->id,$access_token);
                return $user->toArray();
            } else {
                $registerUser = $this->registerUserTw($twInfo,$access_token);
                if ($registerUser !=null)
                    return $registerUser->toArray();
                return false;
            }
        }
    }
    protected function registerUserTw($twInfo,$access_token){
        $table = TableRegistry::get('Users');
        $user = $table->newEntity();
        $user->twitter_id = $twInfo['id_str'];
        $user->email = NULL;
        $user->username = (isset($twInfo['screen_name'])) ? $twInfo['screen_name'] : "";
        $user->full_name = (isset($twInfo['name'])) ? $twInfo['name'] : "";
        $user->avatar_link = (isset($twInfo['profile_image_url'])) ? $twInfo['profile_image_url'] : "";
        $user->access_token = $access_token;
        if ($table->save($user)) 
            return $user;
        return null;
    }
    // Method get user from google oAuth
    protected function checkAccessToken($token){
        $table = TableRegistry::get('Users');
        $user =  $table->find('all')->where(['access_token'=>$token]);
        if (count($user->toArray()) > 0 ) {
            return $user->first();
        }
        return null;
    }
    protected function getUserGgInfo($token){
        $isUser = $this->checkAccessToken($token);
        if ($isUser != null){ Log::info($isUser);
            // Nếu token này đã có trong database thì cho login luôn ko cần quan tâm
            return $isUser->toArray();
        } else {
            // Nếu chưa có token trong database thì đây là token mới, get info token này
            // lấy user_id và và email rồi kiểm tra xem đã có trong database chưa nếu chưa
            // thì đăng kí mới user này, nếu có rồi thì cho login và lưu token mới
            $link = "https://www.googleapis.com/oauth2/v3/userinfo?access_token=".$token;
            $curlSession = curl_init();
            curl_setopt($curlSession, CURLOPT_URL, $link );
            curl_setopt($curlSession, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curlSession,CURLOPT_SSL_VERIFYPEER, false);
            $exec = curl_exec($curlSession);
            $googleInfo = json_decode($exec,true);
            $email = (isset($googleInfo['email'])) ? $googleInfo['email'] : '';
            curl_close($curlSession);
            $user = (isset($googleInfo['sub'])) ? $this->checkUser('google_id',$googleInfo['sub'],$email) : null ;
            Log::info($user);
            if ($user != null) {
                $this->saveToken($user->id,$token);
                return $user->toArray();
            } elseif (is_array($googleInfo) && (!array_key_exists('error', $googleInfo))) {
                $registerUser = $this->registerUserGg($googleInfo,$token);
                if ($registerUser !=null)
                    return $registerUser->toArray();
                return false;
            } else return false;
        }

    }
    protected function saveToken($id,$token){
        $table = TableRegistry::get('Users');
        $user = $table->get($id);
        $user->access_token = $token;
        $table->save($user);
    }
    protected function registerUserGg($googleInfo,$token){
        $table = TableRegistry::get('Users');
        $user = $table->newEntity();
        $user->google_id = $googleInfo['sub'];
        $user->email = (isset($googleInfo['email'])) ? $googleInfo['email'] : NULL;
        $user->username = (isset($googleInfo['name'])) ? $googleInfo['name'] : "";
        $user->avatar_link = (isset($googleInfo['picture'])) ? $googleInfo['picture'] : "";
        $user->access_token = $token;
        if ($table->save($user)) 
            return $user;
        return null;
    }

    // Method get user from facebook OAuth
    
    protected function checkUser($field,$fb_id,$email=''){
        $table = TableRegistry::get('Users');
        $user =  $table->find('all')->where([$field=>$fb_id])->orWhere(['email'=>$email]);
        if (count($user->toArray()) > 0 ) {
            return $user->first();
        }
        return null;
    }
    protected function registerUserFb($facebookInfo){
        $table = TableRegistry::get('Users');
        $user = $table->newEntity();
        $user->facebook_id = $facebookInfo['id'];
        $user->email = (isset($facebookInfo['email'])) ? $facebookInfo['email'] : NULL;
        $user->username = (isset($facebookInfo['name'])) ? $facebookInfo['name'] : "";
        $user->avatar_link = 'http://graph.facebook.com/'.$facebookInfo['id'].'/picture?type=normal';
        if ($table->save($user)) 
            return $user;
        return null;
    }

    protected function getUserFbInfo($token){
        $link = "https://graph.facebook.com/me?fields=id,name,email&access_token=".$token;
        $curlSession = curl_init();
        curl_setopt($curlSession, CURLOPT_URL, $link );
        curl_setopt($curlSession, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlSession,CURLOPT_SSL_VERIFYPEER, false);
        $exec = curl_exec($curlSession);
        $facebookInfo = json_decode($exec,true);
        $email = (isset($facebookInfo['email'])) ? $facebookInfo['email'] : '';
        curl_close($curlSession);
        $user = (isset($facebookInfo['id'])) ? $this->checkUser('facebook_id',$facebookInfo['id'],$email) : null ;
        
        
        if (isset($facebookInfo['id']) && ( $user !=null)){
            return $user->toArray();
        }  else if (is_array($facebookInfo) && (!array_key_exists('error', $facebookInfo))) {
            $registerUser = $this->registerUserFb($facebookInfo);
            if ($registerUser !=null)
                return $registerUser->toArray();
            return false;
        } else if (isset($facebookInfo['error']['error_subcode']) && ($facebookInfo['error']['error_subcode'] == 463)) {
            throw new \ExpiredException('Expired token');
        } else return false;

    }
    /**
     * Get token from header or query string.
     *
     * @param \Cake\Network\Request $request Request object.
     * @return string|bool Token string if found else false.
     */
    protected function _getToken($request)
    {
        $token = $request->env('HTTP_AUTHORIZATION');
        
        
        // @codeCoverageIgnoreStart
        if (!$token && function_exists('getallheaders')) {
            $headers = array_change_key_case(getallheaders());
            if (isset($headers['authorization'])) {
                $token = $headers['authorization'];
            }
        }
        // @codeCoverageIgnoreEnd
        if ($token){
            return $token;
        } else {
            return false;
        }
        

        if (!empty($this->_config['parameter']) &&
            isset($request->query[$this->_config['parameter']])
        ) {
            $token = $request->query($this->_config['parameter']);
        }

        return $token ? $token : false;
    }

    /**
     * Find a user record.
     *
     * @param string $token The token identifier.
     * @param string $password Unused password.
     * @return bool|array Either false on failure, or an array of user data.
     */
    protected function _findUser($token, $password = null)
    {
        try {
            $token = JWT::decode($token, Security::salt(), $this->_config['allowedAlgs']);
        } catch (Exception $e) {
            if (Configure::read('debug')) {
                throw $e;
            }
            return false;
        }

        // Token has full user record.
        if (isset($token->record)) {
            // Trick to convert object of stdClass to array. Typecasting to
            // array doesn't convert property values which are themselves objects.
            return json_decode(json_encode($token->record), true);
        }

        $fields = $this->_config['fields'];

        $table = TableRegistry::get($this->_config['userModel']);
        $conditions = [$table->aliasField($fields['id']) => $token->id];
        if (!empty($this->_config['scope'])) {
            $conditions = array_merge($conditions, $this->_config['scope']);
        }

        $query = $table->find('all')
            ->where($conditions);

        if ($this->_config['contain']) {
            $query = $query->contain($this->_config['contain']);
        }

        $result = $query->first();
        if (empty($result)) {
            return false;
        }

        unset($result[$fields['password']]);
        Log::info($result->toArray());
        return $result->toArray();
    }

    /**
     * Handles an unauthenticated access attempt. Depending on value of config
     * `unauthenticatedException` either throws the specified exception or returns
     * null.
     *
     * @param \Cake\Network\Request $request A request object.
     * @param \Cake\Network\Response $response A response object.
     * @return void
     * @throws \Cake\Network\Exception\UnauthorizedException Or any other
     *   configured exception.
     */
    public function unauthenticated(Request $request, Response $response)
    {
        if (!$this->_config['unauthenticatedException']) {
            return;
        }

        $exception = new $this->_config['unauthenticatedException']($this->_registry->Auth->_config['authError']);
        throw $exception;
    }
}
