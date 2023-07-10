import logo from './logo.svg';
import './App.css';
import axios from 'axios';
import Cookies from 'js-cookie'

import {GenerateJwt, GetPublicKey} from './DpopJwt'

function App() {


  function auth() {
    let params = window.location.toString().split('/');    
    const url = `https://i8cndwe-apim.azure-api.net/test-bff/authorize?scope=openid offline_access`;
    window.location = url;
  }

  function getUserInfo() {
    let csrf_token = Cookies.get('csrf-token');
    let params = window.location.toString().split('/');

    axios.get(`https://i8cndwe-apim.azure-api.net/test-bff/userinfo?scope=openid+offline_access`,
    {
      withCredentials: true,
      headers: { 'X-Token': csrf_token}
    }

    )
      .then((resp) => document.getElementById('msg').innerText = "Hello " + resp.data.name + ",");
  }

  var intervalId = setInterval(function() {
    document.getElementById('rndnum').innerText = "Access Token refreshed at  " + new Date() + ","
    axios.get(`https://i8cndwe-apim.azure-api.net/test-bff/refresh?scope=openid+offline_access`,
    {
      withCredentials: true
    })
  }, 10000);

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <h3 id="msg"></h3>
        <h3 id="rndnum"></h3>
        <div class="btn-group">
          <button id="auth" onClick={auth}>Authorize with External IDP</button>
          <button id="info" onClick={getUserInfo}>Get User Info</button>
        </div>
      </header>
    </div>
  );
}

export default App;
