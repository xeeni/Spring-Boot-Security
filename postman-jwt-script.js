// Add this script to your Login request → Tests tab in Postman

if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("jwtToken", jsonData.token);
    console.log("JWT Token saved:", jsonData.token);
}