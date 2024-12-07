package BOT;

import javacard.framework.*;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;


public class botcard extends Applet
{

	// Cau hinh PIN
	private final static byte PIN_MIN_SIZE = (byte) 4; // Kich thuoc PIN toi thieu
	private final static byte PIN_MAX_SIZE = (byte) 16; // Kich thuoc PIN toi da
	private final static byte[] PIN_INIT_VALUE = {
		(byte) 'B', (byte) 'o', (byte) 't', 
		(byte) 'c', (byte) 'a', (byte) 'r', (byte) 'd'};
		
	//thong tin nguoi dung
	public static byte[] Data = new byte[256];
	public static byte lenData = (byte)0;
	
	public static byte[] infoName;
	public static short lenName = 0;
	public static byte[] infoDob;
	public static short lenDob = 0;
	public static byte[] infoAddress;
	public static short lenAddress= 0;
	public static byte[] infoNumberPlate;
	public static short lenNumberPlate= 0;
	public static byte[] infoImage,size;
	
	// Byte lenh INS cho cac thao tac khac nhau
	private final static byte INS_SETUP = (byte) 0x2A; // Lenh cau hinh
	private final static byte INS_GEN_KEYPAIR = (byte) 0x30; // Lenh tao cap khoa
	private final static byte INS_CREATE_PIN = (byte) 0x40; // Lenh tao PIN
	private final static byte INS_VERIFY_PIN = (byte) 0x42; // Lenh xac minh PIN
	private final static byte INS_CHANGE_PIN = (byte) 0x44; // Lenh doi PIN
	private final static byte INS_UNBLOCK_PIN = (byte) 0x46; // Lenh mo khoa PIN

	// Lenh INS dang xuat va kiem tra dang nhap
	private final static byte INS_LOGOUT_ALL = (byte) 0x60; // Dang xuat tat ca
	private final static byte INS_CHECK_LOGIN = (byte) 0x61; // Kiem tra dang nhap
	
	/////////////////////////////////////////////////
	// APDU data test Huy,2002,HN,12V1-12345
	// 4875792C323030322C484E2C313256312D3132333435
	////////////////////////////////////////////////////
	// Lenh INS cho get / set data
	private final static byte INS_SET_DATA = 0x01;
	private final static byte INS_GET_DATA = 0x02;
	
	// P1 - INS_GET
	private final static byte P1_GET_NAME = 0x01;
	private final static byte P1_GET_DOB = 0x02;
	private final static byte P1_GET_ADDRESS = 0x03;
	private final static byte P1_GET_NUMBER_PLATE = 0x04;
	
	// PIN management
	private static OwnerPIN pin; // PIN hien tai
	private static OwnerPIN unblockin_pin;
	private boolean setupDone = false;
	
	private byte[] tmpBuffer;
	/** ghi trang thai dang nhap*/
	private short loginStatus ;
	//check first connect
	private final static byte[] firstLogin = new byte[]{(byte)0x01};
	
	// Key objects (allocated on demand)
	private Key[] keys;
	//crypt
	private Cipher Cipher;
	private AESKey aesKey;
	private static short KEY_SIZE = 32;
	//define
	private KeyPair[] keyPairs;

	/** Tra ve loi 9C0F khi tham so khong hop le */
	private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;
	/** Tra ve loi 9C0C khi the bi khoa */
	private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
	/** Tra ve loi 9C02 khi nhap sai ma PIN */
	private final static short SW_AUTH_FAILED = (short) 0x9C02;
	/** Tra ve loi khi PIN khong bi khoa */
	private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
	/** Loi noi bo */
	private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
	/** Tra ve loi 9C04 khi the chua duoc cai dat */
	private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
	/** Loi tham so P1 */
	private final static short SW_INCORRECT_P1 = (short) 0x9C10;
	/** Loi tham so P2 */
	private final static short SW_INCORRECT_P2 = (short) 0x9C11;
	/** Thao tac khong duoc phep vi thieu quyen */
	private final static short SW_UNAUTHORIZED = (short) 0x9C06;
	/** Thuat toan duoc chi dinh khong dung */
	private final static short SW_INCORRECT_ALG = (short) 0x9C09;

	
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		if (!KiemTraDoDaiPIN(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length))
		    ISOException.throwIt(SW_INTERNAL_ERROR);
		    
		// Initialize these arrays here
		infoName = new byte[30];
		infoDob = new byte[20];
		infoAddress = new byte[20];
		infoNumberPlate = new byte[15];
		
		lenAddress = 0;
		lenName = 0;
		lenDob = 0;
		lenNumberPlate = 0;
		
		infoImage = new byte[10000];
		size = new byte[7];

		pin = new OwnerPIN((byte) 3, (byte) PIN_INIT_VALUE.length);
		pin.update(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length);
		//register();
		new botcard().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	public boolean select() {
		LogOut();
		return true;
	}

	public void deselect() {
		LogOut();
	}
	public void process(APDU apdu)
	{
		
		byte[] buf = apdu.getBuffer();
		
		 if (selectingApplet()){
			CheckFisrtUse(apdu,buf);
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
		}
		
		apdu.setIncomingAndReceive();
		
		if ((buf[ISO7816.OFFSET_CLA] == 0) && (buf[ISO7816.OFFSET_INS] == (byte) 0xA4))
			return;		
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SETUP:
			setup(apdu,buf);
			break;
		case INS_CREATE_PIN:
			CreatePIN(apdu,buf);
			break;
		case INS_VERIFY_PIN:
			VerifyPIN(apdu,buf);
			break;
		case INS_CHANGE_PIN:
			ChangePIN(apdu,buf);
			break;
		case INS_UNBLOCK_PIN:
			UnblockPIN(apdu,buf);
			break;
		case INS_SET_DATA:
			setData(apdu);
			break;
		case INS_GET_DATA:
			short p1 = buf[ISO7816.OFFSET_P1];
			switch(p1) {
				case P1_GET_NAME:
					getData(apdu, infoName, lenName);
					break;
				case P1_GET_DOB:
					getData(apdu, infoDob, lenDob);
					break;
				case P1_GET_ADDRESS:
					getData(apdu, infoAddress, lenAddress);
					break;
				case P1_GET_NUMBER_PLATE:
					getData(apdu, infoNumberPlate, lenNumberPlate);
					break;
				default:
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void setup(APDU apdu, byte[] buffer) {
		/*
		try {
			tmpBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			tmpBuffer = new byte[(short) 256];
		}
		*/
		firstLogin[0] = (byte)0x00;
		setupDone = true;
	}
	
	private void CreatePIN(APDU apdu, byte[] buffer) {
		byte num_tries = buffer[ISO7816.OFFSET_P2];
		/* Kiem tra dang nhap */
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]); // 05
		if (lenBytePin != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		// toi thieu 1 byte so size pin va 1 byte pin code
		if (lenBytePin < (short)2)
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte pinSize = buffer[ISO7816.OFFSET_CDATA]; // 04
		if (lenBytePin < (short) (1 + pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		pin = new OwnerPIN(num_tries, PIN_MAX_SIZE);
		pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize);
	}
	
	private void VerifyPIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
			
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
			
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		
		if (lenBytePin != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
		if (!KiemTraDoDaiPIN(buffer, ISO7816.OFFSET_CDATA, (byte) lenBytePin))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
			
		if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) lenBytePin)) {
			LogOut();
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		loginStatus  = (short) 0x0010;
	}
	
	private void ChangePIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
			
		short lenBytePin = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		if (apdu.setIncomingAndReceive() != lenBytePin)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if (lenBytePin < (short)4)
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte pinSize = buffer[ISO7816.OFFSET_CDATA];
		if (lenBytePin < (short) (1 + pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		byte newPinSize = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pinSize)];
		if (lenBytePin < (short) (1 + pinSize + newPinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (!KiemTraDoDaiPIN(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pinSize + 1), newPinSize))
			ISOException.throwIt(SW_INVALID_PARAMETER);
			
		if (pin.getTriesRemaining() == (byte) 0x00)
			ISOException.throwIt(SW_IDENTITY_BLOCKED);
			
		if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pinSize)) {
			LogOut();
			ISOException.throwIt(SW_AUTH_FAILED);
		}
		pin.update(buffer, (short)(ISO7816.OFFSET_CDATA + 1 + pinSize + 1), newPinSize);
		
		loginStatus = (short) 0x0010;
	}
	
	private void UnblockPIN(APDU apdu, byte[] buffer) {
		if (pin == null)
			ISOException.throwIt(SW_INCORRECT_P1);
		// Neu ma PIN khong bi chan, khong hop le
		if (pin.getTriesRemaining() != 0)
			ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
		if (buffer[ISO7816.OFFSET_P2] != 0x00)
			ISOException.throwIt(SW_INCORRECT_P2);
		short numBytes = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
		
		if (numBytes != apdu.setIncomingAndReceive())
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		pin.resetAndUnblock();
	}
	
/*KiemTraDoDaiPIN*/
	private static boolean KiemTraDoDaiPIN(byte[] pin_buffer, short pin_offset, byte pin_size) {
		if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
			return false;
		return true;
	}
	private void CheckFisrtUse(APDU apdu,byte[] buffer){
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)1);
		Util.arrayCopy(firstLogin,(short)0,buffer,(short)0,(short)1);
		apdu.sendBytes((short)0,(short)1);
	}
	private void CheckLogin(APDU apdu,byte[] buffer){
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)1);
		byte[] bytelog = new byte[]{(byte)loginStatus};
		Util.arrayCopy(bytelog,(short)0,buffer,(short)0,(short)1);
		apdu.sendBytes((short)0,(short)1);
	}
	private void LogOut() {
		loginStatus  = (short) 0x0000; 
		pin.reset();
	}
	
	// Ham tim vi tri cua dau ngan cach (',' 0x2C)
	private short findDelimiter(byte[] buffer, short offset, short dataLen, byte delimiter) {
		for (short i = offset; i < dataLen; i++) {
			if (buffer[i] == delimiter) {
				return i;
			}
		}
		return dataLen;
	}
	
	// Set data truyen vao cac mang thong tin luu tru
	private void setData(APDU apdu) {
		if (!setupDone) {
			ISOException.throwIt(SW_SETUP_NOT_DONE); // Tr li nu cha setup
		}
		byte[] buffer = apdu.getBuffer();
		short dataLen = buffer[ISO7816.OFFSET_LC];
		short curPos = 0;
		
		short nextDel = findDelimiter(buffer, (short)ISO7816.OFFSET_CDATA, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		
		lenName = (short)(nextDel - ISO7816.OFFSET_CDATA);
		Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, infoName, (short)0, lenName);
		
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		
		lenDob = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoDob, (short)0, lenDob);
		
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		
		lenAddress = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoAddress, (short)0, lenAddress);
		
		curPos = (short) (nextDel + 1);
		nextDel = findDelimiter(buffer, curPos, (short)(ISO7816.OFFSET_CDATA + dataLen), (byte)',');
		
		lenNumberPlate = (short)(nextDel - curPos);
		Util.arrayCopy(buffer, curPos, infoNumberPlate, (short)0, lenNumberPlate);
	}
	
	// dest : Mang chua gia tri, destLength: Do dai mang
	private void getData(APDU apdu, byte[] dest, short destLength) {
		byte[] buffer = apdu.getBuffer();

		// Thiet lap trang thai tra du lieu phan hoi
		apdu.setOutgoing();
		apdu.setOutgoingLength(destLength);

		// Sao chep mang vao buffer
		Util.arrayCopy(dest, (short) 0, buffer, (short) 0, destLength);
		apdu.sendBytes((short) 0, destLength);
	}
}
