#include <M5StickC.h>
#include <SPI.h>
#include <Wire.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include "BLE2902.h"
#include <ArduinoECCX08.h>
#include <utility/ECCX08Cert.h>

#define LGFX_AUTODETECT
#include <LovyanGFX.hpp>

#define SERVICE_UUID_fido BLEUUID((uint16_t)0xfffd)
#define CHARACTERISTIC_UUID_fidoControlPoint "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB"
#define CHARACTERISTIC_UUID_fidoStatus "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB"
#define CHARACTERISTIC_UUID_fidoControlPointLength "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB"
#define CHARACTERISTIC_UUID_fidoServiceRevisionBitfield "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB"
#define CHARACTERISTIC_UUID_fidoServiceRevision BLEUUID((uint16_t)0x2A28)

#define SERVICE_UUID_DeviceInfo BLEUUID((uint16_t)0x180a)
#define CHARACTERISTIC_UUID_ManufacturerName BLEUUID((uint16_t)0x2A29)
#define CHARACTERISTIC_UUID_ModelNumber BLEUUID((uint16_t)0x2A24)
#define CHARACTERISTIC_UUID_FirmwareRevision BLEUUID((uint16_t)0x2A26)

#define DEVICE_NAME "FidoU2fEmulator"
//#define BLE_PASSKEY 123456
#define DISCONNECT_WAIT 3000
#define FIDO_ISSUER "FT FIDO 0200"

static LGFX lcd;

#define PAYLOAD_BUFFER_LENGTH 1024

unsigned short recv_len = 0;
unsigned short expected_len = 0;
unsigned char expected_slot = 0;
unsigned char recv_buffer[PAYLOAD_BUFFER_LENGTH];
unsigned char payload[PAYLOAD_BUFFER_LENGTH];

#define PACKET_BUFFER_SIZE 20

BLECharacteristic *pCharacteristic_fidoControlPoint;
BLECharacteristic *pCharacteristic_fidoStatus;
BLECharacteristic *pCharacteristic_fidoControlPointLength;
BLECharacteristic *pCharacteristic_fidoServiceRevisionBitfield;
BLECharacteristic *pCharacteristic_fidoServiceRevision;

uint8_t value_fidoControlPoint[PACKET_BUFFER_SIZE] = {0x00};
uint8_t value_fidoStatus[PACKET_BUFFER_SIZE] = {0x00};
uint8_t value_fidoControlPointLength[2] = {(PACKET_BUFFER_SIZE >> 8) & 0xff, PACKET_BUFFER_SIZE}; /* Length PACKET_BUFFER_SIZE */
uint8_t value_fidoServiceRevisionBitfield[1] = {0x80};                                            /* Version 1.1 */
uint8_t value_fidoServiceRevision[3] = {0x31, 0x2e, 0x30};                                        /* "1.0" */
uint8_t value_appearance[2] = {0x40, 0x03};

bool connected = false;
BLEAdvertising *g_pAdvertising = NULL;

#define DEFAULT_ISSUER_KEY_SLOT  0
#define DEFAULT_KEY_SLOT  2
#define DEFAULT_DATA_SLOT 8
#define DEFAULT_COUNTER_SLOT 1
#define APPLICATION_LENGTH  32
#define CHALLENGE_LENGTH    32
#define HASH_LENGTH         32
#define RAW_SIGNATURE_LENGTH  64
#define SERIAL_LENGTH       12
#define PUBLICKEY_LENGTH    (1 + 64)
#define KEYHANDLE_LENGTH  (4 + SERIAL_LENGTH)

long auth_prepare(void);
long make_sha256(const unsigned char *p_input, int input_length, unsigned char *p_hash);
long set_signature(const unsigned char *raw_signature, unsigned char *p_payload);
int process_register(const uint8_t *challenge, const uint8_t *application);
int process_authenticate(uint8_t control, const uint8_t *challenge, const uint8_t *application, uint8_t keyHandle_length, const uint8_t *keyHandle);
int process_version(void);

void dump_bin(const char *p_message, const uint8_t *p_bin, unsigned short len)
{
  Serial.printf("%s", p_message);
  for (unsigned short i = 0; i < len; i++){
    Serial.printf("%02x ", p_bin[i]);
  }
  Serial.println("");
}

void lcd_println(const char* p_message, bool clear = true)
{
  if( clear ){
    lcd.fillScreen();
    lcd.setCursor(0, 0);
  }

  lcd.println(p_message);
}

class MyCallbacks : public BLEServerCallbacks
{
  void onConnect(BLEServer *pServer)
  {
    connected = true;
    Serial.println("Connected\n");
    lcd_println("BLE Connected");
  }

  void onDisconnect(BLEServer *pServer)
  {
    connected = false;
    BLE2902 *desc = (BLE2902 *)pCharacteristic_fidoStatus->getDescriptorByUUID(BLEUUID((uint16_t)0x2902));
    desc->setNotifications(false);
    Serial.println("Disconnected\n");
    lcd_println("BLE Disconnected");

    g_pAdvertising->stop();
    delay(DISCONNECT_WAIT);
    g_pAdvertising->start();
    lcd_println("BLE Advertising");
  }
};

class MySecurity : public BLESecurityCallbacks
{
  bool onConfirmPIN(uint32_t pin)
  {
    Serial.println("onConfirmPIN number:");
    Serial.println(pin);
    return false;
  }

  uint32_t onPassKeyRequest()
  {
    Serial.println("onPassKeyRequest");
    return 0;
  }

  void onPassKeyNotify(uint32_t pass_key)
  {
    // ペアリング時のPINの表示
    Serial.println("onPassKeyNotify number");
//    Serial.println(pass_key);
    lcd_println(String(pass_key).c_str(), true);
  }

  bool onSecurityRequest()
  {
    /* ペアリング要否 */
    Serial.println("onSecurityRequest");
    return true;
  }

  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl)
  {
    Serial.println("onAuthenticationComplete");
    if (cmpl.success){
      // ペアリング完了
      Serial.println("auth success");
      lcd_println("Auth Success");
    }else{
      // ペアリング失敗
      Serial.println("auth failed");
      lcd_println("Auth Failed");
    }
  }
};

long auth_prepare(void)
{
  if (!ECCX08.begin(0x35, 32, 33)) {
    Serial.println("No ECCX08 present!");
    return -1;
  }

  if (!ECCX08.locked()) {
    Serial.println("ECCX08 not locked");
    return -1;
  }else{
    Serial.println("ECCX08 locked");
  }

  return 0;
}

long make_keyHandle(unsigned long sequence_no, const unsigned char *serial_no, unsigned char *p_keyHandle)
{
  // ToDo keyhandle may be random
  p_keyHandle[0] = (sequence_no >> 24) & 0xff;
  p_keyHandle[1] = (sequence_no >> 16) & 0xff;
  p_keyHandle[2] = (sequence_no >> 8) & 0xff;
  p_keyHandle[3] = (sequence_no) & 0xff;

  memmove(&p_keyHandle[4], serial_no, SERIAL_LENGTH);

  return 0;
}

long check_keyHandle(const unsigned char *p_keyHandle, unsigned char keyHandle_length, const unsigned char *serial_no)
{
  if( keyHandle_length != KEYHANDLE_LENGTH || memcmp(serial_no, &p_keyHandle[4], SERIAL_LENGTH) != 0 )
    return -1;
  return 0;
}

long make_sha256(const unsigned char *p_input, int input_length, unsigned char *p_hash)
{
  int ret = ECCX08.beginSHA256();
  if( !ret ){
    Serial.println("ECCX08.beginSHA256 Error");
    return -1;
  }
  for( int index = 0 ; index < input_length ; index += 64){
    if( (input_length - index) <= 64 ){
      ECCX08.endSHA256((const byte*)&p_input[index], input_length - index, p_hash);
      if( !ret ){
        Serial.println("ECCX08.endSHA256 Error");
        return -1;
      }
      break;
    }else{
      ECCX08.updateSHA256((const byte*)&p_input[index]);
      if( !ret ){
        Serial.println("ECCX08.updateSHA256 Error");
        return -1;
      }
    }
  }

  return 0;
}

long set_signature(const unsigned char *raw_signature, unsigned char *p_payload)
{
  unsigned char total_len = 0x44;
  int index = 0;
  p_payload[index++] = 0x30;
  index++;
  p_payload[index++] = 0x02;
  if( raw_signature[0] >= 0x80 ){
    p_payload[index++] = 1 + 32;
    p_payload[index++] = 0x00;
    total_len++;
  }else{
    p_payload[index++] = 32;
  }
  memmove(&p_payload[index], &raw_signature[0], 32);
  index += 32;

  p_payload[index++] = 0x02;
  if( raw_signature[32] >= 0x80 ){
    p_payload[index++] = 1 + 32;
    p_payload[index++] = 0x00;
    total_len++;
  }else{
    p_payload[index++] = 32;
  }
  memmove(&p_payload[index], &raw_signature[32], 32);
  index += 32;

  p_payload[1] = total_len;

  return 2 + total_len;
}

int process_register(const uint8_t *challenge, const uint8_t *application)
{
  Serial.println("process_register");

  long ret = auth_prepare();
  if( ret != 0 ){
    Serial.println("auth_prepare error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  uint8_t serial[SERIAL_LENGTH];
  ret = ECCX08.serialNumber(serial);
  if( !ret ){
    Serial.println("serialNumber error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  if (!ECCX08Cert.beginStorage(DEFAULT_KEY_SLOT, DEFAULT_ISSUER_KEY_SLOT)){
    Serial.println("Error starting self signed cert generation!");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  unsigned long counter;
  ret = ECCX08.countUp(DEFAULT_COUNTER_SLOT, &counter);
  if( !ret ){
    Serial.println("ECCX08.countUp Error");
    while (1);
  }

  uint8_t fido_serial[SERIAL_LENGTH + 4];
  memmove(fido_serial, serial, SERIAL_LENGTH);
  fido_serial[SERIAL_LENGTH] = (counter >> 24) & 0xff;
  fido_serial[SERIAL_LENGTH + 1] = (counter >> 16) & 0xff;
  fido_serial[SERIAL_LENGTH + 2] = (counter >> 8) & 0xff;
  fido_serial[SERIAL_LENGTH + 3] = (counter) & 0xff;

  ECCX08Cert.setSerialNumber(fido_serial, sizeof(fido_serial));
  ECCX08Cert.setIssuerName(FIDO_ISSUER);
  ECCX08Cert.setCommonName(String(FIDO_ISSUER) + ECCX08.serialNumber());
  ECCX08Cert.setIssueYear(2022);
  ECCX08Cert.setIssueMonth(1);
  ECCX08Cert.setIssueDay(1);
  ECCX08Cert.setIssueHour(0);
  ECCX08Cert.setExpireYears(10);

  uint8_t *cert;
  int cert_len = ECCX08Cert.endStorage(&cert);
  if( cert_len < 0 ){
    Serial.println("ECCX08SelfSignedCert error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  uint8_t publicKey[PUBLICKEY_LENGTH];
  publicKey[0] = 0x04;
  ret = ECCX08.generatePublicKey(DEFAULT_KEY_SLOT, &publicKey[1]);
  if( !ret ){
    Serial.println("ECCX08.generatePublicKey Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  uint8_t keyHandle[KEYHANDLE_LENGTH];
  unsigned long sequence_no = counter;
  ret = make_keyHandle(sequence_no, serial, keyHandle);
  if( ret != 0 ){
    Serial.println("make_keyHandle Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  int index = 0;
  payload[index++] = 0x05;
  memmove(&payload[index], publicKey, PUBLICKEY_LENGTH);
  index += PUBLICKEY_LENGTH;

  payload[index++] = KEYHANDLE_LENGTH;
  memmove(&payload[index], keyHandle, KEYHANDLE_LENGTH);
  index += KEYHANDLE_LENGTH;

  memmove(&payload[index], cert, cert_len);
  index += cert_len;

  uint8_t input[1 + APPLICATION_LENGTH + CHALLENGE_LENGTH + KEYHANDLE_LENGTH + PUBLICKEY_LENGTH];
  input[0] = 0x00;
  memmove(&input[1], application, APPLICATION_LENGTH);
  memmove(&input[1 + APPLICATION_LENGTH], challenge, CHALLENGE_LENGTH);
  memmove(&input[1 + APPLICATION_LENGTH + CHALLENGE_LENGTH], keyHandle, KEYHANDLE_LENGTH);
  memmove(&input[1 + APPLICATION_LENGTH + CHALLENGE_LENGTH + KEYHANDLE_LENGTH], publicKey, PUBLICKEY_LENGTH);

  unsigned char hash[HASH_LENGTH];
  ret = make_sha256(input, sizeof(input), hash);
  if( ret != 0 ){
    Serial.println("make_sha256 Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  unsigned char signature[RAW_SIGNATURE_LENGTH];
  ret = ECCX08.ecSign(DEFAULT_KEY_SLOT, hash, signature);
  if( !ret ){
    Serial.println("ECCX08.ecSign Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  ret = set_signature(signature, &payload[index]);
  index += ret;

  payload[index++] = 0x90;
  payload[index++] = 0x00;

  return index;
}

int process_authenticate(uint8_t control, const uint8_t *challenge, const uint8_t *application, uint8_t keyHandle_length, const uint8_t *keyHandle)
{
  Serial.println("process_authenticate");

  long ret = auth_prepare();
  if( ret != 0 ){
    Serial.println("auth_prepare error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  uint8_t serial[SERIAL_LENGTH];
  ret = ECCX08.serialNumber(serial);
  if( !ret ){
    Serial.println("serialNumber error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  ret = check_keyHandle(keyHandle, keyHandle_length, serial);
  if( ret != 0 ){
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  if( control == 0x07 ){
    payload[0] = 0x69;
    payload[1] = 0x85;
    return 2;
  }

  unsigned long counter;
  ret = ECCX08.countUp(DEFAULT_COUNTER_SLOT, &counter);
  if( !ret ){
    Serial.println("ECCX08.countUp Error");
    while (1);
  }

  uint8_t userPresence = 0x01;

  unsigned char buffer[APPLICATION_LENGTH + 1 + 4 + CHALLENGE_LENGTH];
  memmove(&buffer[0], application, APPLICATION_LENGTH);
  buffer[APPLICATION_LENGTH] = userPresence;
  buffer[APPLICATION_LENGTH + 1] = (counter >> 24) & 0xff;
  buffer[APPLICATION_LENGTH + 1 + 1] = (counter >> 16) & 0xff;
  buffer[APPLICATION_LENGTH + 1 + 2] = (counter >> 8) & 0xff;
  buffer[APPLICATION_LENGTH + 1 + 3] = (counter) & 0xff;
  memmove(&buffer[APPLICATION_LENGTH + 1 + 4], challenge, CHALLENGE_LENGTH);

  unsigned char hash[HASH_LENGTH];
  ret = make_sha256(buffer, sizeof(buffer), hash);
  if( ret != 0 ){
    Serial.println("make_sha256 Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  unsigned char signature[RAW_SIGNATURE_LENGTH];
  ret = ECCX08.ecSign(DEFAULT_KEY_SLOT, hash, signature);
  if( !ret ){
    Serial.println("ECCX08.ecSign Error");
    payload[0] = 0x6a;
    payload[1] = 0x80;
    return 2;
  }

  int index = 0;
  payload[index++] = userPresence;
  payload[index++] = (counter >> 24) & 0xff;
  payload[index++] = (counter >> 16) & 0xff;
  payload[index++] = (counter >> 8) & 0xff;
  payload[index++] = (counter) & 0xff;
  ret = set_signature(signature, &payload[index]);
  index += ret;

  payload[index++] = 0x90;
  payload[index++] = 0x00;

  return index;
}

int process_version(void)
{
  Serial.println("process_version");

  const static char version[] = "U2F_V2";
  int index = 0;
  memmove(&payload[index], version, strlen(version));
  index += strlen(version);

  payload[index++] = 0x90;
  payload[index++] = 0x00;

  return index;
}

class MyCharacteristicCallbacks : public BLECharacteristicCallbacks
{
  void onWrite(BLECharacteristic *pCharacteristic)
  {
    uint8_t *value = pCharacteristic->getData();
    std::string str = pCharacteristic->getValue();

    dump_bin("onWrite : ", value, str.length());

    if (expected_len > 0 && value[0] != expected_slot)
      expected_len = 0;

    if (expected_len == 0){
      if (value[0] != 0x83)
        return;
      recv_len = 0;
      expected_len = (value[1] << 8) | value[2];
      memmove(&recv_buffer[recv_len], &value[3], str.length() - 3);
      recv_len += str.length() - 3;
      expected_slot = 0;
      if (recv_len < expected_len)
        return;
    }
    else
    {
      memmove(&recv_buffer[recv_len], &value[1], str.length() - 1);
      recv_len += str.length() - 1;
      expected_slot++;
      if (recv_len < expected_len)
        return;
    }
    expected_len = 0;

    int resp_len = 0;
    switch(recv_buffer[1]){
      case 0x01:{
        resp_len = process_register(&recv_buffer[7], &recv_buffer[7 + 32]);
        if( resp_len < 0 ){
          Serial.println("process_registrater Error");
          return;
        }
        break;
      }
      case 0x02:{
        resp_len = process_authenticate(recv_buffer[2], &recv_buffer[7], &recv_buffer[7 + 32], recv_buffer[7 + 32 + 32], &recv_buffer[7 + 32 + 32 + 1]);
        if( resp_len < 0 ){
          Serial.println("process_authenticate Error");
          return;
        }
        break;
      }
      case 0x03:{
        resp_len = process_version();
        if( resp_len < 0 ){
          Serial.println("process_version Error");
          return;
        }
        break;
      }
      default:{
        Serial.println("Unknown INS");
        lcd_println("unknown INS");
        payload[0] = 0x6a;
        payload[1] = 0x80;
        resp_len = 2;
        break;
      }
    }

    int offset = 0;
    int slot = 0;
    int packet_size = 0;
    do{
      if (offset == 0){
        value_fidoStatus[0] = 0x83;
        value_fidoStatus[1] = (resp_len >> 8) & 0xff;
        value_fidoStatus[2] = resp_len & 0xff;
        packet_size = resp_len - offset;
        if (packet_size > (PACKET_BUFFER_SIZE - 3))
          packet_size = PACKET_BUFFER_SIZE - 3;
        memmove(&value_fidoStatus[3], &payload[offset], packet_size);

        dump_bin("Notify : ", value_fidoStatus, packet_size + 3);

        pCharacteristic_fidoStatus->setValue(value_fidoStatus, packet_size + 3);
        pCharacteristic_fidoStatus->notify(true);

        offset += packet_size;
        packet_size += 3;
      }else{
        value_fidoStatus[0] = slot++;
        packet_size = resp_len - offset;
        if (packet_size > (PACKET_BUFFER_SIZE - 1))
          packet_size = PACKET_BUFFER_SIZE - 1;
        memmove(&value_fidoStatus[1], &payload[offset], packet_size);

        dump_bin("Notify : ", value_fidoStatus, packet_size + 1);

        pCharacteristic_fidoStatus->setValue(value_fidoStatus, packet_size + 1);
        pCharacteristic_fidoStatus->notify(true);

        offset += packet_size;
        packet_size += 1;
      }
    } while (packet_size >= PACKET_BUFFER_SIZE);

    lcd_println("process end", false);
  }
};

void taskServer(void *)
{
  BLEDevice::init(DEVICE_NAME);
  /* ESP_BLE_SEC_ENCRYPT_MITM, ESP_BLE_SEC_ENCRYPT */
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT_MITM);
  BLEDevice::setSecurityCallbacks(new MySecurity());

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyCallbacks());

  BLESecurity *pSecurity = new BLESecurity();
  pSecurity->setKeySize(16);
  //  pSecurity->setStaticPIN(BLE_PASSKEY);

  /* ESP_LE_AUTH_NO_BOND, ESP_LE_AUTH_BOND, ESP_LE_AUTH_REQ_MITM */
  //  pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_MITM);
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_BOND);

#ifdef BLE_PASSKEY /* for fixed passkey */
  uint32_t passkey = BLE_PASSKEY;
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t));
#endif

  /* ESP_IO_CAP_IN, ESP_IO_CAP_OUT, ESP_IO_CAP_KBDISP */
  pSecurity->setCapability(ESP_IO_CAP_OUT);
  //  pSecurity->setCapability(ESP_IO_CAP_IN);
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

  BLEService *pService = pServer->createService(SERVICE_UUID_fido);

  pCharacteristic_fidoControlPoint = pService->createCharacteristic(
      CHARACTERISTIC_UUID_fidoControlPoint,
      BLECharacteristic::PROPERTY_WRITE);
  pCharacteristic_fidoControlPoint->setAccessPermissions(ESP_GATT_PERM_WRITE /* ESP_GATT_PERM_WRITE_ENCRYPTED */);
  pCharacteristic_fidoControlPoint->setValue(value_fidoControlPoint, sizeof(value_fidoControlPoint));
  pCharacteristic_fidoControlPoint->setCallbacks(new MyCharacteristicCallbacks());

  pCharacteristic_fidoStatus = pService->createCharacteristic(
      CHARACTERISTIC_UUID_fidoStatus,
      BLECharacteristic::PROPERTY_NOTIFY);
  pCharacteristic_fidoStatus->addDescriptor(new BLE2902());

  pCharacteristic_fidoControlPointLength = pService->createCharacteristic(
      CHARACTERISTIC_UUID_fidoControlPointLength,
      BLECharacteristic::PROPERTY_READ);
  pCharacteristic_fidoControlPointLength->setAccessPermissions(ESP_GATT_PERM_READ);
  pCharacteristic_fidoControlPointLength->setValue(value_fidoControlPointLength, sizeof(value_fidoControlPointLength));

  pCharacteristic_fidoServiceRevisionBitfield = pService->createCharacteristic(
      CHARACTERISTIC_UUID_fidoServiceRevisionBitfield,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE);
  pCharacteristic_fidoServiceRevisionBitfield->setAccessPermissions(ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE);
  pCharacteristic_fidoServiceRevisionBitfield->setValue(value_fidoServiceRevisionBitfield, sizeof(value_fidoServiceRevisionBitfield));

  pCharacteristic_fidoServiceRevision = pService->createCharacteristic(
      CHARACTERISTIC_UUID_fidoServiceRevision,
      BLECharacteristic::PROPERTY_READ);
  pCharacteristic_fidoServiceRevision->setAccessPermissions(ESP_GATT_PERM_READ);
  pCharacteristic_fidoServiceRevision->setValue(value_fidoServiceRevision, sizeof(value_fidoServiceRevision));

  pService->start();

  BLECharacteristic *pCharacteristic;

  BLEService *pService_DeviceInfo = pServer->createService(SERVICE_UUID_DeviceInfo);

  pCharacteristic = pService_DeviceInfo->createCharacteristic(
      CHARACTERISTIC_UUID_ManufacturerName,
      BLECharacteristic::PROPERTY_READ);
  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ);
  pCharacteristic->setValue("SampleModel");

  pCharacteristic = pService_DeviceInfo->createCharacteristic(
      CHARACTERISTIC_UUID_ModelNumber,
      BLECharacteristic::PROPERTY_READ);
  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ);
  pCharacteristic->setValue("M1.0");

  pCharacteristic = pService_DeviceInfo->createCharacteristic(
      CHARACTERISTIC_UUID_FirmwareRevision,
      BLECharacteristic::PROPERTY_READ);
  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ);
  pCharacteristic->setValue("F1.0");

  pService_DeviceInfo->start();

  g_pAdvertising = pServer->getAdvertising();
  g_pAdvertising->addServiceUUID(SERVICE_UUID_fido);
  g_pAdvertising->start();

  lcd_println("BLE Advertising");

  vTaskDelay(portMAX_DELAY); //delay(portMAX_DELAY);
}

void setup()
{
  M5.begin(true, true, true);
  Serial.begin(115200);
  Serial.println("Starting setup");

  lcd.init();
  lcd.setRotation(1);
  lcd.setBrightness(128);
  lcd.fillScreen();
  lcd.setTextSize(2);

  Serial.println("Starting BLE work!");
  xTaskCreate(taskServer, "server", 30000, NULL, 5, NULL);
}

void loop()
{
  if (connected){
    // do something
  }
}
