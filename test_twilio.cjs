const axios = require('axios');

const testCall = async () => {
  const accountSid = process.env.VITE_TWILIO_ACCOUNT_SID
  const authToken = process.env.VITE_TWILIO_AUTH_TOKEN
  const toNumber = process.env.VITE_TWILIO_TO_NUMBER
  const fromNumber = process.env.VITE_TWILIO_FROM_NUMBER

  if (!accountSid || !authToken || !toNumber || !fromNumber) {
    console.log('Twilio config missing. Set VITE_TWILIO_* in .env')
    return
  }

  const twimlXml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
    <Gather numDigits="1" action="https://webhook.site/" method="POST">
        <Say voice="Polly.Matthew-Neural" language="en-US">Test Dynamic Twimlets</Say>
    </Gather>
    <Say voice="Polly.Matthew-Neural">Done.</Say>
</Response>`

  const tEchoUrl = 'https://twimlets.com/echo?Twiml=' + encodeURIComponent(twimlXml)

  const data = new URLSearchParams()
  data.append('To', toNumber)
  data.append('From', fromNumber)
  data.append('Url', tEchoUrl)

  try {
    const res = await axios.post(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Calls.json`, data, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64')
      }
    })
    console.log('Success:', res.data.sid)
  } catch (err) {
    console.log('Twilio Error:', err.response ? err.response.data : err.message)
  }
}
testCall();
