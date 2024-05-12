using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net.Sockets;
using System.Net;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace System.Net.WebSocket {
	public class WebSocketServer {
		private Dictionary<string, WebSocketSession> _ssPool = new Dictionary<string, WebSocketSession>();
		private Socket _svrSk;
		private WebSocketSessionFactory _ssf;

    WebSocketServer() {
			this._ssf = new WebSocketSessionFactory();
		}
		WebSocketServer(WebSocketSessionFactory wssf) {
			this._ssf = wssf;
		}


		#region 启动WebSocket服务
		/// <summary>
		/// 启动WebSocket服务
		/// </summary>
		public void start(int port) {
			_svrSk = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			_svrSk.Bind(new IPEndPoint(IPAddress.Any, port));
			_svrSk.Listen(20);
			_svrSk.BeginAccept(new AsyncCallback(Accept), _svrSk);
		}
		/// <summary>
		/// 停止WebSocket服务
		/// </summary>
		public void Stop() {
			_svrSk.Close();
			foreach(WebSocketSession ws in _ssPool.Values) {
				ws.Socket.Close();
			}
		}
		#endregion

		#region 处理客户端连接请求
		/// <summary>
		/// 处理客户端连接请求
		/// </summary>
		/// <param name="result"></param>
		private void Accept(IAsyncResult ar) {
			// 还原传入的原始套接字
			Socket SockeServer = (Socket)ar.AsyncState;
			// 在原始套接字上调用EndAccept方法，返回新的套接字
			Socket cli = SockeServer.EndAccept(ar);
			try {				
				//保存登录的客户端
				WebSocketSession session = _ssf.CreateClient(cli);

				lock (_ssPool) {
					if (_ssPool.ContainsKey(session.Address)) {
						this._ssPool.Remove(session.Address);
					}
					this._ssPool.Add(session.Address, session);
				}
				//准备接受下一个客户端
				SockeServer.BeginAccept(new AsyncCallback(Accept), SockeServer);
				Console.WriteLine(string.Format("Client {0} connected", cli.RemoteEndPoint));
			}
			catch (Exception ex) {
				Console.WriteLine("Error : " + ex.ToString());
			}
		}
		#endregion

		#region 处理接收的数据
		/// <summary>
		/// 处理接受的数据
		/// </summary>
		/// <param name="socket"></param>
		private void Recieve(IAsyncResult socket) {
			Socket SockeClient = (Socket)socket.AsyncState;
			string IP = SockeClient.RemoteEndPoint.ToString();
			if (SockeClient == null || !_ssPool.ContainsKey(IP)) {
				return;
			}
			try {
				int length = SockeClient.EndReceive(socket);
				byte[] buffer = _ssPool[IP].buffer;
				SockeClient.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(Recieve), SockeClient);
				string msg = Encoding.UTF8.GetString(buffer, 0, length);
				//  websocket建立连接的时候，除了TCP连接的三次握手，websocket协议中客户端与服务器想建立连接需要一次额外的握手动作
				if (msg.Contains("Sec-WebSocket-Key")) {
					SockeClient.Send(PackageHandShakeData(buffer, length));
					_ssPool[IP].isWeb = true;
					return;
				}
				if (_ssPool[IP].isWeb) {
					msg = AnalyzeClientData(buffer, length);
				}
				byte[] msgBuffer = PackageServerData(msg);
				foreach (WebSocketSession se in _ssPool.Values) {
					se.SockeClient.Send(msgBuffer, msgBuffer.Length, SocketFlags.None);
				}
			}
			catch {
				SockeClient.Disconnect(true);
				Console.WriteLine("客户端 {0} 断开连接", IP);
				_ssPool.Remove(IP);
			}
		}
		#endregion

		#region 客户端和服务端的响应
		/*
         * 客户端向服务器发送请求
         * 
         * GET / HTTP/1.1
         * Origin: http://localhost:1416
         * Sec-WebSocket-Key: vDyPp55hT1PphRU5OAe2Wg==
         * Connection: Upgrade
         * Upgrade: Websocket
         *Sec-WebSocket-Version: 13
         * User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
         * Host: localhost:8064
         * DNT: 1
         * Cache-Control: no-cache
         * Cookie: DTRememberName=admin
         * 
         * 服务器给出响应
         * 
         * HTTP/1.1 101 Switching Protocols
         * Upgrade: websocket
         * Connection: Upgrade
         * Sec-WebSocket-Accept: xsOSgr30aKL2GNZKNHKmeT1qYjA=
         * 
         * 在请求中的“Sec-WebSocket-Key”是随机的，服务器端会用这些数据来构造出一个SHA-1的信息摘要。把“Sec-WebSocket-Key”加上一个魔幻字符串
         * “258EAFA5-E914-47DA-95CA-C5AB0DC85B11”。使用 SHA-1 加密，之后进行 BASE-64编码，将结果做为 “Sec-WebSocket-Accept” 头的值，返回给客户端
         */
		#endregion

		#region 打包请求连接数据
		/// <summary>
		/// 打包请求连接数据
		/// </summary>
		/// <param name="handShakeBytes"></param>
		/// <param name="length"></param>
		/// <returns></returns>
		private byte[] PackageHandShakeData(byte[] handShakeBytes, int length) {
			string handShakeText = Encoding.UTF8.GetString(handShakeBytes, 0, length);
			string key = string.Empty;
			Regex reg = new Regex(@"Sec\-WebSocket\-Key:(.*?)\r\n");
			Match m = reg.Match(handShakeText);
			if (m.Value != "") {
				key = Regex.Replace(m.Value, @"Sec\-WebSocket\-Key:(.*?)\r\n", "$1").Trim();
			}
			byte[] secKeyBytes = SHA1.Create().ComputeHash(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
			string secKey = Convert.ToBase64String(secKeyBytes);
			var responseBuilder = new StringBuilder();
			responseBuilder.Append("HTTP/1.1 101 Switching Protocols" + "\r\n");
			responseBuilder.Append("Upgrade: websocket" + "\r\n");
			responseBuilder.Append("Connection: Upgrade" + "\r\n");
			responseBuilder.Append("Sec-WebSocket-Accept: " + secKey + "\r\n\r\n");
			return Encoding.UTF8.GetBytes(responseBuilder.ToString());
		}
		#endregion

		#region 处理接收的数据
		/// <summary>
		/// 处理接收的数据
		/// 参考 http://www.cnblogs.com/smark/archive/2012/11/26/2789812.html
		/// </summary>
		/// <param name="recBytes"></param>
		/// <param name="length"></param>
		/// <returns></returns>
		private string AnalyzeClientData(byte[] recBytes, int length) {
			int start = 0;
			// 如果有数据则至少包括3位
			if (length < 2)
				return "";
			// 判断是否为结束针
			bool IsEof = (recBytes[start] >> 7) > 0;
			// 暂不处理超过一帧的数据
			if (!IsEof)
				return "";
			start++;
			// 是否包含掩码
			bool hasMask = (recBytes[start] >> 7) > 0;
			// 不包含掩码的暂不处理
			if (!hasMask)
				return "";
			// 获取数据长度
			UInt64 mPackageLength = (UInt64)recBytes[start] & 0x7F;
			start++;
			// 存储4位掩码值
			byte[] Masking_key = new byte[4];
			// 存储数据
			byte[] mDataPackage;
			if (mPackageLength == 126) {
				// 等于126 随后的两个字节16位表示数据长度
				mPackageLength = (UInt64)(recBytes[start] << 8 | recBytes[start + 1]);
				start += 2;
			}
			if (mPackageLength == 127) {
				// 等于127 随后的八个字节64位表示数据长度
				mPackageLength = (UInt64)(recBytes[start] << (8 * 7) | recBytes[start] << (8 * 6) | recBytes[start] << (8 * 5) | recBytes[start] << (8 * 4) | recBytes[start] << (8 * 3) | recBytes[start] << (8 * 2) | recBytes[start] << 8 | recBytes[start + 1]);
				start += 8;
			}
			mDataPackage = new byte[mPackageLength];
			for (UInt64 i = 0; i < mPackageLength; i++) {
				mDataPackage[i] = recBytes[i + (UInt64)start + 4];
			}
			Buffer.BlockCopy(recBytes, start, Masking_key, 0, 4);
			for (UInt64 i = 0; i < mPackageLength; i++) {
				mDataPackage[i] = (byte)(mDataPackage[i] ^ Masking_key[i % 4]);
			}
			return Encoding.UTF8.GetString(mDataPackage);
		}
		#endregion

	}

	public class WebSocketSessionFactory {

		public virtual WebSocketSession CreateClient(Socket sk) {
			return new WebSocketSession(sk);
		}
	}

	public class WebSocketSession {
		private Socket _sk;
		private bool _isweb;
		private bool _isFirstData;

		public Socket Socket {get { return _sk; }}
		public byte[] buffer { set; get; }
		public string Address {get { return _sk.RemoteEndPoint.ToString(); }}
		public bool isWeb {set { _isweb = value; } get { return _isweb; }}

		public WebSocketSession(Socket sk) {
			this._sk = sk;
			_isweb = false;
			_isFirstData = true;
			buffer = new byte[4096];
			//接收客户端的数据
			this._sk.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(Recieve), this);
			onConnect();
		}
		/// <summary>
		/// 处理接受的数据
		/// </summary>
		/// <param name="socket"></param>
		private void Recieve(IAsyncResult ar) {
			WebSocketSession ss = (WebSocketSession)ar.AsyncState;
			if (ss == null) {return;}
			try {
				int length = ss.Socket.EndReceive(ar);
				byte[] buffer = ss.buffer;
				ss.Socket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, new AsyncCallback(Recieve), ss);
				//websocket建立连接的时候，除了TCP连接的三次握手，websocket协议中客户端与服务器想建立连接需要一次额外的握手动作(一般是第一个数据)
				if (_isFirstData) {
					_isFirstData = false;
					ss.Socket.Send(PackageHandShakeData(buffer, length));
					return;
				}
				string msg = AnalyzeClientData(buffer, length);

				byte[] msgBuffer = PackageServerData(msg);
				foreach (WebSocketSession se in SessionPool.Values) {
					se.SockeClient.Send(msgBuffer, msgBuffer.Length, SocketFlags.None);
				}
			}
			catch {
				sk.Disconnect(true);
				Console.WriteLine("客户端 {0} 断开连接", IP);
				SessionPool.Remove(IP);
			}
		}
		/// <summary>
		/// 握手处理
		/// </summary>
		/// <param name="handShakeBytes"></param>
		/// <param name="length"></param>
		/// <returns></returns>
		private byte[] PackageHandShakeData(byte[] handShakeBytes, int length) {
			string handShakeText = Encoding.UTF8.GetString(handShakeBytes, 0, length);
			string key = string.Empty;
			Regex reg = new Regex(@"Sec\-WebSocket\-Key:(.*?)\r\n");
			Match m = reg.Match(handShakeText);
			if (m.Value != "") {
				key = Regex.Replace(m.Value, @"Sec\-WebSocket\-Key:(.*?)\r\n", "$1").Trim();
			}
			byte[] secKeyBytes = SHA1.Create().ComputeHash(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
			string secKey = Convert.ToBase64String(secKeyBytes);
			var responseBuilder = new StringBuilder();
			responseBuilder.Append("HTTP/1.1 101 Switching Protocols" + "\r\n");
			responseBuilder.Append("Upgrade: websocket" + "\r\n");
			responseBuilder.Append("Connection: Upgrade" + "\r\n");
			responseBuilder.Append("Sec-WebSocket-Accept: " + secKey + "\r\n\r\n");
			return Encoding.UTF8.GetBytes(responseBuilder.ToString());
		}

		/// <summary>
		/// 处理接收的数据
		/// 参考 http://www.cnblogs.com/smark/archive/2012/11/26/2789812.html
		/// </summary>
		/// <param name="recBytes"></param>
		/// <param name="length"></param>
		/// <returns></returns>
		private string AnalyzeClientData(byte[] recBytes, int length) {
			int start = 0;
			// 如果有数据则至少包括3位
			if (length < 2)
				return "";
			// 判断是否为结束针
			bool IsEof = (recBytes[start] >> 7) > 0;
			// 暂不处理超过一帧的数据
			if (!IsEof)
				return "";
			start++;
			// 是否包含掩码
			bool hasMask = (recBytes[start] >> 7) > 0;
			// 不包含掩码的暂不处理
			if (!hasMask)
				return "";
			// 获取数据长度
			UInt64 mPackageLength = (UInt64)recBytes[start] & 0x7F;
			start++;
			// 存储4位掩码值
			byte[] Masking_key = new byte[4];
			// 存储数据
			byte[] mDataPackage;
			if (mPackageLength == 126) {
				// 等于126 随后的两个字节16位表示数据长度
				mPackageLength = (UInt64)(recBytes[start] << 8 | recBytes[start + 1]);
				start += 2;
			}
			if (mPackageLength == 127) {
				// 等于127 随后的八个字节64位表示数据长度
				mPackageLength = (UInt64)(recBytes[start] << (8 * 7) | recBytes[start] << (8 * 6) | recBytes[start] << (8 * 5) | recBytes[start] << (8 * 4) | recBytes[start] << (8 * 3) | recBytes[start] << (8 * 2) | recBytes[start] << 8 | recBytes[start + 1]);
				start += 8;
			}
			mDataPackage = new byte[mPackageLength];
			for (UInt64 i = 0; i < mPackageLength; i++) {
				mDataPackage[i] = recBytes[i + (UInt64)start + 4];
			}
			Buffer.BlockCopy(recBytes, start, Masking_key, 0, 4);
			for (UInt64 i = 0; i < mPackageLength; i++) {
				mDataPackage[i] = (byte)(mDataPackage[i] ^ Masking_key[i % 4]);
			}
			return Encoding.UTF8.GetString(mDataPackage);
		}

		public int Send(byte[] buffer) {
			byte[] content = null;
			if (buffer.Length < 126) {
				content = new byte[buffer.Length + 2];
				content[0] = 0x81;
				content[1] = (byte)buffer.Length;
				Buffer.BlockCopy(buffer, 0, content, 2, buffer.Length);
			}
			else if (buffer.Length < 0xFFFF) {
				content = new byte[buffer.Length + 4];
				content[0] = 0x81;
				content[1] = 126;
				content[2] = (byte)(buffer.Length >> 8 & 0xFF);
				content[3] = (byte)(buffer.Length & 0xFF);
				Buffer.BlockCopy(buffer, 0, content, 4, buffer.Length);
			}
			else {
				content = new byte[buffer.Length + 10];
				content[0] = 0x81;
				content[1] = 127;
				content[2] = (byte)(buffer.Length >> 56 & 0xFF);
				content[3] = (byte)(buffer.Length >> 48 & 0xFF);
				content[4] = (byte)(buffer.Length >> 40 & 0xFF);
				content[5] = (byte)(buffer.Length >> 32 & 0xFF);
				content[6] = (byte)(buffer.Length >> 24 & 0xFF);
				content[7] = (byte)(buffer.Length >> 16 & 0xFF);
				content[8] = (byte)(buffer.Length >> 8 & 0xFF);
				content[9] = (byte)(buffer.Length & 0xFF);
				Buffer.BlockCopy(buffer, 0, content, 10, buffer.Length);
			}
			return _sk.Send(content);

		}

		public int Send(string msg) {
			byte[] buffer = Encoding.UTF8.GetBytes(msg);
			return Send(buffer);
		}

		public virtual void onConnect() { }
		public virtual void onMessage(string data) { }
		public virtual void onError(string data) { }
		public virtual void onClose(string data) { }
	}

}
