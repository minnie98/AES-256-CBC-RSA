package AES_256_CBC;

import java.net.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class E2EEChat {
	private Socket clientSocket = null;

	public Socket getSocketContext() {
		return clientSocket;
	}

	// 접속 정보, 필요시 수정
	private final String hostname = "homework.islab.work";
	private final int port = 8080;

	public E2EEChat() throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		clientSocket = new Socket();
		clientSocket.connect(new InetSocketAddress(hostname, port));

		InputStream stream = clientSocket.getInputStream();

		Thread senderThread = new Thread(new messageSender(this));
		senderThread.start();

		while (true) {
			try {
				if (clientSocket.isClosed() || !senderThread.isAlive()) {
					break;
				}

				byte[] recvBytes = new byte[2048];
				int recvSize = stream.read(recvBytes);

				if (recvSize == 0) {
					continue;
				}

				String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

				parseReceiveData(recv);
			} catch (IOException ex) {
				System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
				break;
			}
		}

		try {
			System.out.println("입력 스레드가 종료될때까지 대기중...");
			senderThread.join();

			if (clientSocket.isConnected()) {
				clientSocket.close();
			}
		} catch (InterruptedException ex) {
			System.out.println("종료되었습니다.");
		}
	}

	public void parseReceiveData(String recvData)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		// 여기부터 3EPROTO 패킷 처리를 개시합니다.

		String method = ""; // Received payload에서 METHOD 저장 변수

		/* payload 한 줄씩 파싱 */
		StringTokenizer st = new StringTokenizer(recvData, "\n");
		String[] array = new String[st.countTokens()];
		int i = 0;
		while (st.hasMoreElements()) {
			array[i++] = st.nextToken();

		}
		/* payload의 첫 줄인 3EPROTO와 METHOD 토큰화 */
		StringTokenizer st_method = new StringTokenizer(array[0], " ");
		String[] array2 = new String[st_method.countTokens()];
		i = 0;
		while (st_method.hasMoreElements()) {
			array2[i++] = st_method.nextToken();
		}

		method = array2[1];
//		System.out.println("***[parseReceiveData] METHOD is : " + method);

		if (method.equals("KEYXCHG")) { // KEYXCHG method인 경우 //RSA 공개키 교환
			if (this.keyXCHG_RSA(recvData)) { // KEYXCHG 성공할 경우 KEYXCHGOK method로 저장
				recvData = "3EPROTO KEYXCHGOK" + "\n" + array[1] + "\n" + array[2] + "\n" + array[3] + "\n";

			} else { // KEYXCHG 실패할 경우 KEYXCHGFAIL method로 저장
				recvData = "3EPROTO KEYXCHGFAIL" + "\n" + array[1] + "\n" + array[2] + "\n" + array[3] + "\n";
			}

		} else if (method.equals("KEYXCHGRST")) { // KEYXCHGRST method인 경우 // RSA의 공캐기로 암호화 된 세션키 교환
			if (this.keyXCHG(recvData)) { // KEYXCHG 성공할 경우 KEYXCHGOK method로 저장
				recvData = "3EPROTO KEYXCHGOK" + "\n" + array[1] + "\n" + array[2] + "\n" + array[3] + "\n";

			} else { // KEYXCHG 실패할 경우 KEYXCHGFAIL method로 저장
				recvData = "3EPROTO KEYXCHGFAIL" + "\n" + array[1] + "\n" + array[2] + "\n" + array[3] + "\n";
			}
		} else if (method.equals("MSGRECV")) { // MSGRECV method일 경우 // 세션키로 암호화 된 메시지 수신 

			try {
				recvData = array[0] + "\n" + array[1] + "\n" + array[2] + "\n" + array[3] + "\n\n"
						+ this.MSGRECV(recvData);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		System.out.println(recvData + "\n*=*=*=*= recv =*=*=*=*");
	}

	/* RSA 개인키로 복호화 */
	static byte[] DecryptRSA(byte[] CipherKey) throws Exception {

		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, privateKey);
		return c.doFinal(CipherKey);

	}

	/* RSA 공개키로 암호화 */
	static byte[] EncryptRSA(byte[] SessionKey) throws Exception {

		Cipher c = Cipher.getInstance("RSA");

		c.init(Cipher.ENCRYPT_MODE, publicKey);
		return c.doFinal(SessionKey);

	}

	public static Key publicKey; //공개키 
	public static Key privateKey; //개인키 

	/* RSA 키 생성 */
	public static void generatorRSAKey() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();

	}

	/* AES 키 생성 */
	static byte[] generateAESkey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		generator.init(256, random); // 키 256비트(64바이트) 크기로 생성
		SecretKey AESKey = generator.generateKey();

		byte[] iv = new byte[16]; // iv는 128비트(32바이트)
		new SecureRandom().nextBytes(iv);

		byte[] IVAES = new byte[16 + AESKey.getEncoded().length];

		System.arraycopy(iv, 0, IVAES, 0, 16); // IV
		System.arraycopy(AESKey.getEncoded(), 0, IVAES, 16, AESKey.getEncoded().length); // AES KEY

		return IVAES;
	}

	/* AES 암호화 */
	static byte[] EncryptAES(String PlainText, byte[] keyBytes, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));

		return c.doFinal(PlainText.getBytes());
	}

	/* AES 복호화 */
	static String DecryptAES(byte[] Ciphertext, byte[] keyBytes, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
		return new String(c.doFinal(Ciphertext));
	}

	HashMap<String, String[]> USERS = new HashMap<String, String[]>(); // key: ID, value: AESKey, IV

	public boolean keyXCHG(String str) throws InvalidKeySpecException, NoSuchAlgorithmException { // RSA 공개키로 암호화 된 세션키
																									// 교환
		String senderID = ""; // payload에서 From의 ID

		// payload 한줄 씩 파싱
		StringTokenizer st = new StringTokenizer(str, "\n");
		String[] array = new String[st.countTokens()];
		int i = 0;
		while (st.hasMoreElements()) {
			array[i++] = st.nextToken();
//			System.out.println("***[keyXCHG] array[" + (i - 1) + "] = " + array[i - 1]);

		}

		senderID = array[2].substring(5, array[2].length());
		byte[] key = Base64.getDecoder().decode(array[5]);
		byte[] iv = Base64.getDecoder().decode(array[6]);

		String[] values = this.USERS.get(senderID);// values[0]: RSA로 암호화 된 세션키, values[1]: IV, values[2]: RSA 공개키

		values[2] = values[2];
		values[1] = Base64.getEncoder().encodeToString(iv);
		values[0] = Base64.getEncoder().encodeToString(key);

//		System.out.println("***[keyXCHG] Encryted key : " + values[0]);
//		System.out.println("***[keyXCHG] iv : " + values[1]);

		USERS.put(senderID, values); // USERS 해시맵에 Sender의 ID를 키 값으로 해당 ID의 AES key와 IV 저장

		if (key != null && iv != null) { // 성공적으로 put 됐을 경우 return true
			return true;
		}

		return false; // 실패하면 return false
	}

	public boolean keyXCHG_RSA(String str) throws InvalidKeySpecException, NoSuchAlgorithmException { // 공개키 교환
		String senderID = ""; // payload에서 From의 ID

		// payload 한줄 씩 파싱
		StringTokenizer st = new StringTokenizer(str, "\n");
		String[] array = new String[st.countTokens()];
		int i = 0;
		while (st.hasMoreElements()) {
			array[i++] = st.nextToken();
//			System.out.println("***[keyXCHG_RSA] array[" + (i - 1) + "] = " + array[i - 1]);

		}

		senderID = array[2].substring(5, array[2].length());
		byte[] key = Base64.getDecoder().decode(array[5]);
		byte[] iv = Base64.getDecoder().decode(array[6]);

		String[] values = new String[3];// values[0]: RSA로 암호화 된 세션키, values[1]: IV, values[2]: RSA 공개키

		values[2] = Base64.getEncoder().encodeToString(key);
		values[1] = Base64.getEncoder().encodeToString(iv);
		values[0] = "";

//		System.out.println("***[keyXCHG_RSA] public key : " + values[2]);
//		System.out.println("***[keyXCHG_RSA] iv : " + values[1]);

		USERS.put(senderID, values); // USERS 해시맵에 Sender의 ID를 키 값으로 해당 ID의 AES key와 IV 저장

		if (key != null && iv != null) { // 성공적으로 put 됐을 경우 return true
			return true;
		}

		return false; // 실패하면 return false
	}

	public String MSGRECV(String str) throws Exception {

		String recvmsg = ""; // payload에서 body에 해당
		String senderID = ""; // payload에서 from에 해당

		// payload 한줄 씩 파싱
		StringTokenizer st = new StringTokenizer(str, "\n");
		String[] array = new String[st.countTokens()];
		int i = 0;
		while (st.hasMoreElements()) {
			array[i++] = st.nextToken();
//			System.out.println("***[MSGRECV] array[" + (i - 1) + "] = " + array[i - 1]);

		}

		senderID = array[2].substring(5, array[2].length());
		String[] value = this.USERS.get(senderID);
		byte[] encrypted = Base64.getDecoder().decode(array[4]); // 세션키로 암호화된 메시지

		byte[] key = Base64.getDecoder().decode(value[0]); // 공개키로 암호화 된 세션 키 
		byte[] iv = Base64.getDecoder().decode(value[1]);
		byte[] publickey_ = Base64.getDecoder().decode(value[2]);

//		System.out.println("***[MSGRECV] Encrypted key: " + Base64.getEncoder().encodeToString(key));
//		System.out.println("***[MSGRECV] iv: " + Base64.getEncoder().encodeToString(iv));

		key = E2EEChat.DecryptRSA(key); // 개인키로 공개키로 암호화 된 세션키 복호화
//		System.out.println("***[MSGRECV] Session key: " + Base64.getEncoder().encodeToString(key));
		recvmsg = DecryptAES(encrypted, key, iv); // 세션키로 암호화된 메시지 복호화

//		System.out.println("***[MSGRECV] senderID: " + senderID);
//		System.out.println("***[MSGRECV] recvmsg: " + recvmsg);

		return recvmsg;
	}

	// 필요한 경우 추가로 메서드를 정의하여 사용합니다.
	public static void main(String[] args)
			throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		try {
			new E2EEChat();
		} catch (UnknownHostException ex) {
			System.out.println("연결 실패, 호스트 정보를 확인하세요.");
		} catch (IOException ex) {
			System.out.println("소켓 통신 중 문제가 발생하였습니다.");
		}
	}
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class messageSender implements Runnable {
	E2EEChat clientContext;
	OutputStream socketOutputStream;

	public messageSender(E2EEChat context) throws IOException {
		clientContext = context;

		Socket clientSocket = clientContext.getSocketContext();
		socketOutputStream = clientSocket.getOutputStream();
	}

	// 암호화
	@Override
	public void run() {
		Scanner scanner = new Scanner(System.in);
		String message = "";
		String in1 = "";
		String in2 = "";
		String in3 = "";
		String in4 = "";
		String in5 = "";
		String in6 = "";
		String in7 = "";

		byte[] IVAES = null;
		try {
			IVAES = E2EEChat.generateAESkey();
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} // 초기화 벡터 + AES키

		byte[] iv = Arrays.copyOfRange(IVAES, 0, 16); // 초기화벡터 IV
		byte[] aesKey = Arrays.copyOfRange(IVAES, 16, IVAES.length); // byte형 AES
		try {
			E2EEChat.generatorRSAKey();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		byte[] encryptedSessionKey = null;
		try {
			encryptedSessionKey = E2EEChat.EncryptRSA(aesKey); // session key를 공개키로 암호화
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException
				| IllegalBlockSizeException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		while (true) {
			try {
				System.out.println("MESSAGE: ");

				in1 = scanner.nextLine().trim(); // payload 첫 번째 줄 입력
				in2 = scanner.nextLine().trim(); // payload 두 번째 줄 입력
				if (in1.equals("3EPROTO CONNECT") || in1.equals("3EPROTO DISCONNECT")) { // method가 CONNECT인 경우
					message = in1 + "\n" + in2 + "\n";
				} else if (in1.equals("3EPROTO KEYXCHG")) { // method가 KEYXCHG인 경우 //공개키 교환

					in3 = scanner.nextLine().trim(); // payload 세 번째 줄 입력
					in4 = scanner.nextLine().trim(); // payload 네 번째 줄 입력
//					in6 = Base64.getEncoder().encodeToString(aesKey); // 생성된 KEY
//					in7 = Base64.getEncoder().encodeToString(iv); // 생성된 IV
					in6 = Base64.getEncoder().encodeToString(E2EEChat.publicKey.getEncoded()); // RSA 공개키
					in7 = Base64.getEncoder().encodeToString(iv);

					message = in1 + "\n" + in2 + "\n" + in3 + "\n" + in4 + "\n\n\n" + in6 + "\n" + in7 + "\n"; // payload
																												// 구축

				} else if (in1.equals("3EPROTO KEYXCHGRST")) { // method가 KEYXCHGRST인 경우 //공개키로 암호화된 세션키 교환
					in3 = scanner.nextLine().trim(); // payload 세 번째 줄 입력
					in4 = scanner.nextLine().trim(); // payload 네 번째 줄 입력
					in6 = Base64.getEncoder().encodeToString(encryptedSessionKey); // AES 키를 RSA로 암호화
					in7 = Base64.getEncoder().encodeToString(iv); // 생성된 IV
//					in6 = Base64.getEncoder().encodeToString(encryptedSessionKey); // IV+ AES 키를 RSA로 암호화
//					in7 = Base64.getEncoder().encodeToString(iv);

					message = in1 + "\n" + in2 + "\n" + in3 + "\n" + in4 + "\n\n\n" + in6 + "\n" + in7 + "\n"; // payload
																												// 구축

				} else { // MSGSEND

					in3 = scanner.nextLine().trim(); // payload 세 번째 줄 입력
					in4 = scanner.nextLine().trim(); // payload 네 번째 줄 입력
					in5 = scanner.nextLine().trim(); // payload 다섯번째 줄 입력
					in6 = scanner.nextLine().trim(); // message //body 입력

					// 세션키로 메시지(body) 암호화해서 전송
					in6 = Base64.getEncoder().encodeToString(E2EEChat.EncryptAES(in6, aesKey, iv));
					message = in1 + "\n" + in2 + "\n" + in3 + "\n" + in4 + "\n" + in5 + "\n" + in6 + "\n"; // payload 구축
				}

				// server로 전송는 코드
				byte[] payload = message.getBytes(StandardCharsets.UTF_8);

				socketOutputStream.write(payload, 0, payload.length);
			} catch (IOException ex) {
				break;
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		System.out.println("msgSender runnable end");
		scanner.close();
	}
}