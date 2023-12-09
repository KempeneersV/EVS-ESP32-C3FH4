//////////////////////////////////////////////////

// Include SPIFFS library
#include "SPIFFS.h"
// Include I2C library
#include "Wire.h"
// Include certificate data
#include "cert.h"
#include "private_key.h"

// Include ArduinoJson library
#include <ArduinoJson.h>


// For ESP32_SC_W5500
#define DEBUG_ETHERNET_WEBSERVER_PORT       Serial

// Debug Level from 0 to 4
#define _ETHERNET_WEBSERVER_LOGLEVEL_       3

// Library used to control W5500 chip
#include <WebServer_ESP32_SC_W5500.h>

// We define two new HTTP-Header names. Those headers will be used internally
// to store the user name and group after authentication. If the client provides
// these headers, they will be ignored to prevent authentication bypass.
#define HEADER_USERNAME "X-USERNAME"
#define HEADER_GROUP    "X-GROUP"

// Library used to create HTTPS server
#include <HTTPS_Server_Generic.h>

//////////////////////////////////////////////////////////

// SPI bus pins

#define MISO_GPIO           2
#define MOSI_GPIO           7
#define SCK_GPIO            6

// W5500 pins
#define ETH_SPI_HOST        SPI2_HOST
#define W5500_CLOCK_MHZ     25
#define W5500_INT_GPIO      5
#define W5500_CS_GPIO       8

// Led pin for debug on board
#define ledPin              10 

// I2C pins
# define SDA_PIN 0
# define SCL_PIN 1
# define I2C_FREQUENCY 100000

// PCF8574AN I2C address
#define PCF8574AN_ADDRESS 0x38

// Enter a MAC address and IP address for your controller below.
#define NUMBER_OF_MAC      20

// Store server sates
uint8_t backupServerStates = 0; 

byte mac[][NUMBER_OF_MAC] =
{
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x01 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x02 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x03 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x04 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x05 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x06 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x07 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x08 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x09 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x0A },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x0B },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x0C },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x0D },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x0E },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x0F },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x10 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x11 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x12 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0x13 },
  { 0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0x14 },
};

//////////////////////////////////////////////////

// Select the IP address according to your local network
IPAddress myIP(192, 168, 2, 232);
IPAddress myGW(192, 168, 2, 1);
IPAddress mySN(255, 255, 255, 0);

// Google DNS Server IP
IPAddress myDNS(8, 8, 8, 8);

// The HTTPS Server comes in a separate namespace. For easier use, include it here.
using namespace httpsserver;

// Create an SSL certificate object from the files included above
SSLCert cert = SSLCert(
                 example_crt_DER, example_crt_DER_len,
                 example_key_DER, example_key_DER_len
               );

// Create an SSL-enabled server that uses the certificate
// The contstructor takes some more parameters, but we go for default values here.
HTTPSServer secureServer = HTTPSServer(&cert);

//////////////////////////////////////////////////

void blinkLED(int numBlinks, int blinkDuration = 1000) {
  for (int i = 0; i < numBlinks; ++i) {
    digitalWrite(ledPin, HIGH);  // Turn on the LED
    delay(blinkDuration);

    digitalWrite(ledPin, LOW);   // Turn off the LED
    delay(blinkDuration);
  }
}

bool writeToPCF8574AN(uint8_t state) {
  Wire.begin(SDA_PIN, SCL_PIN, I2C_FREQUENCY); 
  
  // Send data to PCF8574AN
  Wire.beginTransmission(PCF8574AN_ADDRESS);
  Wire.write(state);
  int result = Wire.endTransmission();

  if (result == 0) {
    // Transmission réussie
    Serial.println("Transmission réussie");
    return true;
  } else {
    // Erreur lors de la transmission
    Serial.print("Erreur de transmission. Code d'erreur : ");
    Serial.println(result);
    // return false;
    return true; // for debug
  }
}

// Reads the content of an HTML file from the SPIFFS file system
// and sends it as the response to an HTTP client.
void printHtmlFile(HTTPResponse *res, String filename) {
  // Open the specified file in read mode
  File file = SPIFFS.open(filename, "r");
  // Check if the file was opened successfully
  if (!file) {
    Serial.println("Failed to open file for reading");
    return;
  }
  // Set the Content-Type to HTML in the HTTP response header
  res->setHeader("Content-Type", "text/html");

  // Read and send the file content character by character
  while (file.available()) {
    char c = file.read();

    // Write the current character to the HTTP response
    res->write(c);
  }

  // Close the file now that its content has been sent
  file.close();
}

//////////////////////////////////////////////////

// Declare a middleware function.
// Parameters:
// req: Request data, can be used to access URL, HTTP Method, Headers, ...
// res: Response data, can be used to access HTTP Status, Headers, ...
// next: This function is used to pass control down the chain. If you have done your work
//       with the request object, you may decide if you want to process the request.
//       If you do so, you call the next() function, and the next middleware function (if
//       there is any) or the actual requestHandler will be called.
//       If you want to skip the request, you do not call next, and set for example status
//       code 403 on the response to show that the user is not allowed to access a specific
//       resource.
//       For more details, see the definition below.

/**
   The following middleware function is one of two functions dealing with access control. The
   middlewareAuthentication() will interpret the HTTP Basic Auth header, check usernames and password,
   and if they are valid, set the X-USERNAME and X-GROUP header.

   If they are invalid, the X-USERNAME and X-GROUP header will be unset. This is important because
   otherwise the client may manipulate those internal headers.

   Having that done, further middleware functions and the request handler functions will be able to just
   use req->getHeader("X-USERNAME") to find out if the user is logged in correctly.

   Furthermore, if the user supplies credentials and they are invalid, he will receive an 401 response
   without any other functions being called.
*/
void middlewareAuthentication(HTTPRequest * req, HTTPResponse * res, std::function<void()> next)
{
  // Unset both headers to discard any value from the client
  // This prevents authentication bypass by a client that just sets X-USERNAME
  req->setHeader(HEADER_USERNAME, "");
  req->setHeader(HEADER_GROUP, "");

  // Get login information from request
  // If you use HTTP Basic Auth, you can retrieve the values from the request.
  // The return values will be empty strings if the user did not provide any data,
  // or if the format of the Authorization header is invalid (eg. no Basic Method
  // for Authorization, or an invalid Base64 token)
  std::string reqUsername = req->getBasicAuthUser();
  std::string reqPassword = req->getBasicAuthPassword();

  // If the user entered login information, we will check it
  if (reqUsername.length() > 0 && reqPassword.length() > 0)
  {

    // _Very_ simple hardcoded user database to check credentials and assign the group
    bool authValid = true;
    std::string group = "";

    if (reqUsername == "admin" && reqPassword == "secret")
    {
      group = "ADMIN";
    }
    else
    {
      authValid = false;
    }

    // If authentication was successful
    if (authValid)
    {
      // set custom headers and delegate control
      req->setHeader(HEADER_USERNAME, reqUsername);
      req->setHeader(HEADER_GROUP, group);

      // The user tried to authenticate and was successful
      // -> We proceed with this request.
      next();
    }
    else
    {
      // Display error page
      res->setStatusCode(401);
      res->setStatusText("Unauthorized");
      res->setHeader("Content-Type", "text/plain");

      // This should trigger the browser user/password dialog, and it will tell
      // the client how it can authenticate
      res->setHeader("WWW-Authenticate", "Basic realm=\"ESP32 privileged area\"");

      // Small error text on the response document. In a real-world scenario, you
      // shouldn't display the login information on this page, of course ;-)
      res->println("401. Unauthorized (try admin/secret)");

      // NO CALL TO next() here, as the authentication failed.
      // -> The code above did handle the request already.
    }
  }
  else
  {
    // No attempt to authenticate
    // -> Let the request pass through by calling next()
    next();
  }
}

/**
   This function plays together with the middlewareAuthentication(). While the first function checks the
   username/password combination and stores it in the request, this function makes use of this information
   to allow or deny access.

   This example only prevents unauthorized access to every ResourceNode stored under an /internal/... path.
*/
void middlewareAuthorization(HTTPRequest * req, HTTPResponse * res, std::function<void()> next)
{
  // Get the username (if any)
  std::string username = req->getHeader(HEADER_USERNAME);

  // Check that only logged-in users may get to the internal area (All URLs starting with /internal)
  // Only a simple example, more complicated configuration is up to you.
  if (username == "" && req->getRequestString().substr(0, 9) == "/admin")
  {
    // Same as the deny-part in middlewareAuthentication()
    res->setStatusCode(401);
    res->setStatusText("Unauthorized");
    res->setHeader("Content-Type", "text/plain");
    res->setHeader("WWW-Authenticate", "Basic realm=\"ESP32 privileged area\"");
    res->println("401. Unauthorized (try admin/secret or user/test)");

    // No call denies access to protected handler function.
  }
  else
  {
    // Everything else will be allowed, so we call next()
    next();
  }
}

void handleAdminPage(HTTPRequest * req, HTTPResponse * res)
{
  // Headers
  res->setHeader("Content-Type", "text/html; charset=utf8");

  // Checking permissions can not only be done centrally in the middleware function but also in the actual request handler.
  // This would be handy if you provide an API with lists of resources, but access rights are defined object-based.
  if (req->getHeader(HEADER_GROUP) == "ADMIN")
  {
    res->setStatusCode(200);
    res->setStatusText("OK");
    // res->printStd(header);
    printHtmlFile(res, "/admin.html");

  }
  else
  {
    // res->printStd(header);
    res->setStatusCode(403);
    res->setStatusText("Unauthorized");
    res->println("<p><strong>403 Unauthorized</strong> You have no power here!</p>");
  }
}

// For details on the implementation of the hanlder functions, refer to the Static-Page example.
void handleRoot(HTTPRequest * req, HTTPResponse * res)
{
  res->setHeader("Content-Type", "text/html");
  printHtmlFile(res, "/public.html");
}

// Handles incoming POST requests containing server state data.
void handlePostServerStates(HTTPRequest *req, HTTPResponse *res) {
  Serial.println("POST request received");

  // Get the content length of the request
  int contentLength = req->getContentLength();
  Serial.print("Data length: ");
  Serial.println(contentLength);

  if (contentLength > 0) {
    // Allocate a buffer_char to store the incoming data
    char *buffer_char = new char[contentLength + 1];

    // Read the incoming data into the buffer_char
    size_t bytesRead = req->readChars(buffer_char, contentLength);
    buffer_char[bytesRead] = '\0'; // Null-terminate the string

    // Process the received data
    Serial.println("Received data: ");
    Serial.println(buffer_char);

    // Convert the received binary string to an array of integers
    int j = 0;
    int *buffer_int = new int[9];
    for (int i = 0; i < contentLength; i++) {
      if (buffer_char[i] == '1') {
        buffer_int[j] = 1;
        j++;
      } else if (buffer_char[i] == '0') {
        buffer_int[j] = 0;
        j++;
      }
    }

    // Convert the array of integers to a single byte representing server states
    uint8_t serverStates = 0;
    for (int i = 0; i < 8; i++) {
      serverStates |= buffer_int[i] << (7 - i);
    }
    Serial.println("serverStates :");
    Serial.println(serverStates, BIN);

    // Free allocated memory for the buffers
    delete[] buffer_char;
    delete[] buffer_int;

    // Send the processed data to the PCF8574AN and handle the response
    if (writeToPCF8574AN(serverStates)) {
      // Save the serverStates value (backup)
      backupServerStates = serverStates;
      Serial.println(backupServerStates, BIN);
      Serial.println("Data sent to PCF8574AN");
      res->setHeader("Content-Type", "application/json");
      res->println("{\"message\": \"Data received successfully\"}");
    } else {
      Serial.println("Error while sending data to PCF8574AN");
      res->setHeader("Content-Type", "application/json");
      res->println("{\"message\": \"Error while sending data to PCF8574AN\"}");
    }
  } else {
    Serial.println("No data received");
    res->setHeader("Content-Type", "application/json");
    res->println("{\"message\": \"No Data received\"}");
  }
}

// Handles incoming GET requests to retrieve server states.
void handleGetServerStates(HTTPRequest *req, HTTPResponse *res) {
  Serial.println("GET request for server states received");

  // Create a JSON object to hold server states
  DynamicJsonDocument jsonDocument(1024); // Adjust the size as needed
  JsonArray serverStatesArray = jsonDocument.createNestedArray("serverStates");

  // Allocate memory for buffer_int
  int *buffer_int = new int[8]; 

  for (int i = 7; i >= 0; i--) {
      buffer_int[i] = (backupServerStates >> (7 - i)) & 1;
  }

  // Populate serverStatesArray with data from buffer_int and calculate backupServerStates
  Serial.println("Buffer_int values:");
  for (int i = 0; i < 8; i++) {
    serverStatesArray.add(buffer_int[i]);

    // Debug print each value of buffer_int
    Serial.print("buffer_int[");
    Serial.print(i);
    Serial.print("]: ");
    Serial.println(buffer_int[i]);
  }
  
  // Free allocated memory for buffer_int
  delete[] buffer_int;

  // Serialize JSON to a string
  String jsonString;
  serializeJson(jsonDocument, jsonString);

  // Debug print the JSON string
  Serial.print("JSON Response: ");
  Serial.println(jsonString);

  // Set response headers
  res->setHeader("Content-Type", "application/json");
  res->setHeader("Cache-Control", "no-cache");

  // Send the server states as a JSON response
  res->println(jsonString);
}


void handle404(HTTPRequest * req, HTTPResponse * res)
{
  req->discardRequestBody();
  res->setStatusCode(404);
  res->setStatusText("Not Found");
  res->setHeader("Content-Type", "text/html");
  res->println("<!DOCTYPE html>");
  res->println("<html>");
  res->println("<head><title>Not Found</title></head>");
  res->println("<body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body>");
  res->println("</html>");
}

void setup()
{
  // Starting serial
  Serial.begin(115200);

  while (!Serial && millis() < 5000);

  delay(500);

  pinMode(ledPin, OUTPUT);

  // Starting SPIFFS
  Serial.println("Starting SPIFFS...");
  int startTime = millis();
  while (!SPIFFS.begin(true) ) {
    if (millis() - startTime > 5000) {
      Serial.println("SPIFFS Mount Failed");
    }
    digitalWrite(ledPin, HIGH);
    while (1);
  }

  ///////////////////////////////////

  // To be called before ETH.begin()
  ESP32_W5500_onEvent();

  // start the ethernet connection and the server:
  // Use DHCP dynamic IP and random mac
  uint16_t index = millis() % NUMBER_OF_MAC;

  //bool begin(int MISO_GPIO, int MOSI_GPIO, int SCLK_GPIO, int W5500_CS_GPIO, int W5500_INT_GPIO, int W5500_CLOCK_MHZ,
  //           int SPI_HOST, uint8_t *W5500_Mac = W5500_Default_Mac);
  ETH.begin( MISO_GPIO, MOSI_GPIO, SCK_GPIO, W5500_CS_GPIO, W5500_INT_GPIO, W5500_CLOCK_MHZ, ETH_SPI_HOST, mac[index] );


  // Static IP, comment this line to get IP via DHCP
  //bool config(IPAddress local_ip, IPAddress gateway, IPAddress subnet, IPAddress dns1 = 0, IPAddress dns2 = 0);
  ETH.config(myIP, myGW, mySN, myDNS);

  ESP32_W5500_waitForConnect();

  ///////////////////////////////////

  Serial.print(F("HTTPS EthernetWebServer is @ IP : "));
  Serial.println(ETH.localIP());

  Serial.print(F("To access, use https://"));
  Serial.println(ETH.localIP());

  ///////////////////////////////////////////////

  // For every resource available on the server, we need to create a ResourceNode
  // The ResourceNode links URL and HTTP method to a handler function
  // GET
  ResourceNode * nodeRoot     = new ResourceNode("/", "GET", &handleRoot);
  ResourceNode * nodeAdmin    = new ResourceNode("/admin", "GET", &handleAdminPage);
    ResourceNode *nodeGetStates = new ResourceNode("/getServerStates", "GET", &handleGetServerStates);
  ResourceNode * node404      = new ResourceNode("", "GET", &handle404);

  // POST
  ResourceNode * nodeState = new ResourceNode("/postServerStates", "POST", &handlePostServerStates);


  // Add the nodes to the server
  secureServer.registerNode(nodeRoot);
  secureServer.registerNode(nodeAdmin);
  secureServer.registerNode(nodeState);
  secureServer.registerNode(nodeGetStates);
  // Add the 404 not found node to the server.
  // The path is ignored for the default node.
  secureServer.setDefaultNode(node404);

  // Add the middleware. These functions will be called globally for every request
  // Note: The functions are called in the order they are added to the server.
  // This means, we need to add the authentication middleware first, because the
  // authorization middleware needs the headers that will be set by the authentication
  // middleware (First we check the identity, then we see what the user is allowed to do)
  secureServer.addMiddleware(&middlewareAuthentication);
  secureServer.addMiddleware(&middlewareAuthorization);

  Serial.println("Starting server...");
  secureServer.start();

  if (secureServer.isRunning())
  {
    Serial.println("Server ready.");
    blinkLED(3);
  }

}

void loop()
{
  // This call will let the server do its work
  secureServer.loop();
  if(secureServer.isRunning()) {
  blinkLED(1, 100);
  }
}