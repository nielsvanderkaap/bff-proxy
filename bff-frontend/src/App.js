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

  function getUserInfoWithJwt() {
    let csrf_token = Cookies.get('csrf-token');
    let params = window.location.toString().split('/');

    GenerateJwt()
    .then((resp) => document.getElementById('msg').innerText = resp);

    GetPublicKey()
    .then((resp) => document.getElementById('publickey').innerText = JSON.stringify(resp));
  }

  getUserInfoWithJwt()

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <h3 id="msg">aa</h3>
        <h3 id="publickey">aa</h3>
        <div class="btn-group">
          <button id="auth" onClick={auth}>Authorize with External IDP</button>
          <button id="info" onClick={getUserInfo}>Get User Info</button>
          <button id="info-jwt" onClick={getUserInfoWithJwt}>Get User Info with JWT</button>
        </div>
      </header>
    </div>
  );
}

export default App;
