const axios = require('axios');

const apiIndex = async function (req, res){
    res.status(200).json('Welcome to the SingPass Node API');
}

const apiCheck = async function (req, res){
    res.status(200).json('Welcome to the SingPass API');
}

const getProfile = async function (req, res){
      const uinfin = req.body.uinfin;
      let config = {
        method: 'get',
        maxBodyLength: Infinity,
        url: 'https://sandbox.api.myinfo.gov.sg/com/v4/person-sample',
        params: {
            uinfin: uinfin
        },
        headers: {}
      };

      try {
        const response = await axios.request(config);
        res.status(200).json(response.data);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user profile', message: error.message });
      }
}

module.exports = { apiIndex, apiCheck, getProfile }