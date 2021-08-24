#ifndef CRYPTOGRAPHY_MD5_HPP
#define CRYPTOGRAPHY_MD5_HPP

#include <string>
#include <vector>
#include <sstream>
#include <functional>
#include <any>

typedef unsigned char byte;

///<< Todo : Add Another Event Implementaiton
struct EventArgs
{
};

class StringHelper
{
public:
	static std::string toHex(uint32_t num)
	{
		std::stringstream stream;
		stream << std::hex << num;
		return stream.str();
	}
};

namespace Crypto
{
	/**
	 *  @brief 
	 *      class for changing event args
	 */
	class MD5ChangingEventArgs : public EventArgs
	{
	public:
		const std::vector<byte> NewData;

		/**
         * @brief Construct a new MD5ChangingEventArgs object
         * 
         * @param data 
         */
		MD5ChangingEventArgs(std::vector<byte> &data);

		/**
         * @brief Construct a new MD5ChangingEventArgs object
         * 
         * @param data 
         */
		MD5ChangingEventArgs(const std::string &data);
	};

	/**
     *  @brief 
     *      class for changed event args
     */
	class MD5ChangedEventArgs : public EventArgs
	{
	public:
		const std::vector<byte> NewData;
		/*const*/ std::string Value;

		/**
         * @brief Construct a new MD5ChangedEventArgs object
         * 
         * @param data 
         * @param HashedValue 
         */
		MD5ChangedEventArgs(std::vector<byte> &data, const std::string &HashedValue);

		/**
         * @brief Construct a new MD5ChangedEventArgs object
         * 
         * @param data 
         * @param HashedValue 
         */
		MD5ChangedEventArgs(const std::string &data, const std::string &HashedValue);
	};

	class Md5
	{
		///<< Initial constants for md5
	public:
		enum class MD5InitializerConstant : uint32_t
		{
			A = 0x67452301,
			B = 0xEFCDAB89,
			C = 0x98BADCFE,
			D = 0X10325476
		};

		///<< Represent digest with ABCD
	public:
		class Digest
		{
		public:
			uint32_t A = 0;
			uint32_t B = 0;
			uint32_t C = 0;
			uint32_t D = 0;

			Digest();

			std::string ToHexString();
		};

		///<< helper class providing suporting function
	public:
		class Md5Helper
		{
		private:
			Md5Helper();

		public:
			/**
             *  @brief 
             *      Left rotates the input word
             * 
             *  @param uiNumber 
             *      a value to be rotated
             * 
             *  @param shift 
             *      no of bits to be rotated
             * 
            *   @return 
            *       the rotated value
            */

			static uint32_t RotateLeft(uint32_t uiNumber, unsigned short shift);

			/** 
             *  @brief
             *      perform a ByteReversal on a number
             * 
			 *  @param uiNumber 
             *      value to be reversed
             * 
			 *  @return 
             *      reversed value
            */
			static uint32_t ReverseByte(uint32_t uiNumber);
		};

		///< lookup table 4294967296*sin(i)

	private:
		const static std::vector<uint32_t> T;

		///< X used to proces data in
		///< 512 bits chunks as 16 32 bit word

		std::vector<uint32_t> X = std::vector<uint32_t>(16);

		///< the finger print obtained.
		Digest *_digest;

		///< the input bytes
		std::vector<byte> _byteInput;

		using ValueChanging = std::function<void(std::any sender, MD5ChangingEventArgs *Changing)>;

		using ValueChanged = std::function<void(std::any sender, MD5ChangedEventArgs *Changed)>;

	public:
		EventHelper<ValueChanging> *OnValueChanging = new EventHelper<ValueChanging>();

		EventHelper<ValueChanged> *OnValueChanged = new EventHelper<ValueChanged>();

		///<gets or sets as string
		virtual ~Md5()
		{
			delete _digest;
		}

		std::string getStringValue() const;
		void setStringValue(const std::string &value);

		///< get/sets as  byte array
		std::vector<byte> getBytesValue() const;
		void setBytesValue(std::vector<byte> &value);

		/**
		 * 	@brief 
		 * 		gets the signature/fignerprint as hex string
		 * 
		 * 	@return std::string 
		 */
		std::string getHexDigest() const;

	private:
		/**
		 * 	@brief 
		 * 		calculat md5 signature of the string in Input
		 * 
		 * 	@return Digest* 
		 * 		the finger print of msg
		 */
		Digest *CalculateMD5Value();

		/********************************************************
		 * TRANSFORMATIONS :  FF , GG , HH , II  acc to RFC 1321
		 * where each Each letter represnets the aux function used
		 *********************************************************/

	protected:
		/**
		 * 	@brief
		 *		perform transformatio using f(((b&c) | (~(b)&d))
		 */
		void TransF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i);

		/**
		 * 	@brief 
		 * 		perform transformatio using g((b&d) | (c & ~d) ) 
		 */
		void TransG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i);

		/**
		 *  @brief 
		 *  	perform transformatio using h(b^c^d)
		 */
		void TransH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i);

		/**
		 * 	@brief 
		 * 		perform transformatio using i (c^(b|~d))
		 */
		void TransI(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i);

		/**
		 *  @brief 
		 */
		void PerformTransformation(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D);

		/**
		 * 	@brief
		 * 		Create Padded buffer for processing , buffer is padded with 0 along
		 * 		with the size in the end
		 * 
		 * 	@return std::vector<byte>
		 * 		the padded buffer as byte array
		 */
		std::vector<byte> CreatePaddedBuffer();

		/**
		 * 	@brief
		 * 		Copies a 512 bit block into X as 16 32 bit words 
		 * 
		 * 	@param bMsg 
		 * 		source buffer
		 * 
		 * 	@param block 
		 * 		no of block to copy starting from 0
		 */
		void CopyBlock(std::vector<byte> &bMsg, uint32_t block);

		///< Constructor

	public:
		Md5();
	};
}

#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

template <typename T>
class EventHelper final
{
private:
	std::unordered_map<std::string, T> namedListeners;

public:
	void addListener(const std::string &methodName, T namedEventHandlerMethod)
	{
		if (namedListeners.find(methodName) == namedListeners.end())
			namedListeners[methodName] = namedEventHandlerMethod;
	}
	void removeListener(const std::string &methodName)
	{
		if (namedListeners.find(methodName) != namedListeners.end())
			namedListeners.erase(methodName);
	}

private:
	std::vector<T> anonymousListeners;

public:
	void addListener(T unnamedEventHandlerMethod)
	{
		anonymousListeners.push_back(unnamedEventHandlerMethod);
	}

	std::vector<T> listeners()
	{
		std::vector<T> allListeners;
		for (auto listener : namedListeners)
		{
			allListeners.push_back(listener.second);
		}
		allListeners.insert(allListeners.end(), anonymousListeners.begin(), anonymousListeners.end());
		return allListeners;
	}

	void invoke(std::any sender, MD5ChangingEventArgs Changing)
	{
		T(sender, Changing);
	}

	void invoke(std::any sender, MD5ChangedEventArgs Changing)
	{
		T(sender, Changing);
	}
};

namespace Crypto
{

	MD5ChangingEventArgs::MD5ChangingEventArgs(std::vector<byte> &data)
	{
		auto NewData = std::vector<byte>(data.size());
		for (int i = 0; i < data.size(); i++)
		{
			NewData[i] = data[i];
		}
	}

	MD5ChangingEventArgs::MD5ChangingEventArgs(const std::string &data)
	{
		auto NewData = std::vector<byte>(data.length());
		for (int i = 0; i < data.length(); i++)
		{
			NewData[i] = static_cast<byte>(data[i]);
		}
	}

	MD5ChangedEventArgs::MD5ChangedEventArgs(std::vector<byte> &data, const std::string &HashedValue)
	{
		auto NewData = std::vector<byte>(data.size());
		for (int i = 0; i < data.size(); i++)
		{
			NewData[i] = data[i];
		}
		Value = HashedValue;
	}

	MD5ChangedEventArgs::MD5ChangedEventArgs(const std::string &data, const std::string &HashedValue)
	{
		auto NewData = std::vector<byte>(data.length());
		for (int i = 0; i < data.length(); i++)
		{
			NewData[i] = static_cast<byte>(data[i]);
		}

		Value = HashedValue;
	}

	Md5::Digest::Digest()
	{
		A = static_cast<uint32_t>(MD5InitializerConstant::A);
		B = static_cast<uint32_t>(MD5InitializerConstant::B);
		C = static_cast<uint32_t>(MD5InitializerConstant::C);
		D = static_cast<uint32_t>(MD5InitializerConstant::D);
	}

	std::string Md5::Digest::ToHexString()
	{
		std::string st;
		st = StringHelper::toHex(Md5Helper::ReverseByte(A)) +
			 StringHelper::toHex(Md5Helper::ReverseByte(B)) +
			 StringHelper::toHex(Md5Helper::ReverseByte(C)) +
			 StringHelper::toHex(Md5Helper::ReverseByte(D));

		return st;
	}

	Md5::Md5Helper::Md5Helper()
	{
	}

	uint32_t Md5::Md5Helper::RotateLeft(uint32_t uiNumber, unsigned short shift)
	{
		return ((uiNumber >> 32 - shift) | (uiNumber << shift));
	}

	uint32_t Md5::Md5Helper::ReverseByte(uint32_t uiNumber)
	{
		return (((uiNumber & 0x000000ff) << 24) | (uiNumber >> 24) | ((uiNumber & 0x00ff0000) >> 8) | ((uiNumber & 0x0000ff00) << 8));
	}

	const std::vector<uint32_t> Md5::T = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

	std::string Md5::getStringValue() const
	{
		std::string st;
		auto tempCharArray = std::vector<wchar_t>(_byteInput.size());

		for (int i = 0; i < _byteInput.size(); i++)
		{
			tempCharArray[i] = static_cast<wchar_t>(_byteInput[i]);
		}

		st = std::string(tempCharArray.begin(), tempCharArray.end());
		return st;
	}

	void Md5::setStringValue(const std::string &value)
	{
		///< raise the event to notify the changing
		if (OnValueChanging != nullptr)
		{
			MD5ChangingEventArgs tempVar(value);
			OnValueChanging->invoke(this, &tempVar);
		}

		_byteInput = std::vector<byte>(value.length());
		for (int i = 0; i < value.length(); i++)
		{
			_byteInput[i] = static_cast<byte>(value[i]);
		}
		_digest = CalculateMD5Value();

		///< raise the event to notify the change
		if (OnValueChanged != nullptr)
		{
			MD5ChangedEventArgs tempVar2(value, _digest->ToHexString());
			OnValueChanged->invoke(this, &tempVar2);
		}
	}

	std::vector<byte> Md5::getBytesValue() const
	{
		auto bt = std::vector<byte>(_byteInput.size());
		for (int i = 0; i < _byteInput.size(); i++)
		{
			bt[i] = _byteInput[i];
		}
		return bt;
	}

	void Md5::setBytesValue(std::vector<byte> &value)
	{
		///< raise the event to notify the changing
		if (OnValueChanging != nullptr)
		{
			MD5ChangingEventArgs tempVar(value);
			OnValueChanging->invoke(this, &tempVar);
		}

		_byteInput = std::vector<byte>(value.size());
		for (int i = 0; i < value.size(); i++)
		{
			_byteInput[i] = value[i];
		}
		_digest = CalculateMD5Value();

		///< notify the changed  value
		if (OnValueChanged != nullptr)
		{
			MD5ChangedEventArgs tempVar2(value, _digest->ToHexString());
			OnValueChanged->invoke(this, &tempVar2);
		}
	}

	std::string Md5::getHexDigest() const
	{
		return _digest->ToHexString();
	}

	Md5::Digest *Md5::CalculateMD5Value()
	{
		std::vector<byte> bMsg; //buffer to hold bits
		uint32_t N;				//N is the size of msg as  word (32 bit)
		auto dg = new Digest(); //  the value to be returned

		// create a buffer with bits padded and length is alos padded
		bMsg = CreatePaddedBuffer();

		N = static_cast<uint32_t>(bMsg.size() * 8) / 32; //no of 32 bit blocks

		for (uint32_t i = 0; i < N / 16; i++)
		{
			CopyBlock(bMsg, i);
			PerformTransformation(dg->A, dg->B, dg->C, dg->D);
		}
		return dg;
	}

	void Md5::TransF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i)
	{
		a = b + Md5Helper::RotateLeft((a + ((b & c) | (~*(static_cast<uint32_t *>(&d)))) + X[k] + T[i - 1]), s);
	}

	void Md5::TransG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i)
	{
		a = b + Md5Helper::RotateLeft((a + ((b & d) | (c & ~d)) + X[k] + T[i - 1]), s);
	}

	void Md5::TransH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i)
	{
		a = b + Md5Helper::RotateLeft((a + (b ^ c ^ d) + X[k] + T[i - 1]), s);
	}

	void Md5::TransI(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t k, unsigned short s, uint32_t i)
	{
		a = b + Md5Helper::RotateLeft((a + (c ^ (b | ~d)) + X[k] + T[i - 1]), s);
	}

	void Md5::PerformTransformation(uint32_t &A, uint32_t &B, uint32_t &C, uint32_t &D)
	{
		///<< saving  ABCD  to be used in end of loop

		uint32_t AA, BB, CC, DD;

		AA = A;
		BB = B;
		CC = C;
		DD = D;

		/* Round 1
		    * [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
		    * [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
		    * [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
		    * [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
		    *  * */
		TransF(A, B, C, D, 0, 7, 1);
		TransF(D, A, B, C, 1, 12, 2);
		TransF(C, D, A, B, 2, 17, 3);
		TransF(B, C, D, A, 3, 22, 4);
		TransF(A, B, C, D, 4, 7, 5);
		TransF(D, A, B, C, 5, 12, 6);
		TransF(C, D, A, B, 6, 17, 7);
		TransF(B, C, D, A, 7, 22, 8);
		TransF(A, B, C, D, 8, 7, 9);
		TransF(D, A, B, C, 9, 12, 10);
		TransF(C, D, A, B, 10, 17, 11);
		TransF(B, C, D, A, 11, 22, 12);
		TransF(A, B, C, D, 12, 7, 13);
		TransF(D, A, B, C, 13, 12, 14);
		TransF(C, D, A, B, 14, 17, 15);
		TransF(B, C, D, A, 15, 22, 16);
		/** ROUND 2
		    **[ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
		    *[ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
		    *[ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
		    *[ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
		*/
		TransG(A, B, C, D, 1, 5, 17);
		TransG(D, A, B, C, 6, 9, 18);
		TransG(C, D, A, B, 11, 14, 19);
		TransG(B, C, D, A, 0, 20, 20);
		TransG(A, B, C, D, 5, 5, 21);
		TransG(D, A, B, C, 10, 9, 22);
		TransG(C, D, A, B, 15, 14, 23);
		TransG(B, C, D, A, 4, 20, 24);
		TransG(A, B, C, D, 9, 5, 25);
		TransG(D, A, B, C, 14, 9, 26);
		TransG(C, D, A, B, 3, 14, 27);
		TransG(B, C, D, A, 8, 20, 28);
		TransG(A, B, C, D, 13, 5, 29);
		TransG(D, A, B, C, 2, 9, 30);
		TransG(C, D, A, B, 7, 14, 31);
		TransG(B, C, D, A, 12, 20, 32);
		/*  ROUND 3
         * [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
         * [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
         * [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
         * [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
        **/
		TransH(A, B, C, D, 5, 4, 33);
		TransH(D, A, B, C, 8, 11, 34);
		TransH(C, D, A, B, 11, 16, 35);
		TransH(B, C, D, A, 14, 23, 36);
		TransH(A, B, C, D, 1, 4, 37);
		TransH(D, A, B, C, 4, 11, 38);
		TransH(C, D, A, B, 7, 16, 39);
		TransH(B, C, D, A, 10, 23, 40);
		TransH(A, B, C, D, 13, 4, 41);
		TransH(D, A, B, C, 0, 11, 42);
		TransH(C, D, A, B, 3, 16, 43);
		TransH(B, C, D, A, 6, 23, 44);
		TransH(A, B, C, D, 9, 4, 45);
		TransH(D, A, B, C, 12, 11, 46);
		TransH(C, D, A, B, 15, 16, 47);
		TransH(B, C, D, A, 2, 23, 48);
		/*ROUND  4
			*[ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
		    *[ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
		    *[ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
		    *[ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
		**/
		TransI(A, B, C, D, 0, 6, 49);
		TransI(D, A, B, C, 7, 10, 50);
		TransI(C, D, A, B, 14, 15, 51);
		TransI(B, C, D, A, 5, 21, 52);
		TransI(A, B, C, D, 12, 6, 53);
		TransI(D, A, B, C, 3, 10, 54);
		TransI(C, D, A, B, 10, 15, 55);
		TransI(B, C, D, A, 1, 21, 56);
		TransI(A, B, C, D, 8, 6, 57);
		TransI(D, A, B, C, 15, 10, 58);
		TransI(C, D, A, B, 6, 15, 59);
		TransI(B, C, D, A, 13, 21, 60);
		TransI(A, B, C, D, 4, 6, 61);
		TransI(D, A, B, C, 11, 10, 62);
		TransI(C, D, A, B, 2, 15, 63);
		TransI(B, C, D, A, 9, 21, 64);

		A = A + AA;
		B = B + BB;
		C = C + CC;
		D = D + DD;
	}
	std::vector<unsigned char> Md5::CreatePaddedBuffer()
	{
		uint32_t pad;										///< no of padding bits for 448 mod 512
		std::vector<unsigned char> bMsg;					///< buffer to hold bits
		unsigned long long sizeMsg;							///< 64 bit size pad
		uint32_t sizeMsgBuff;								///< buffer size in multiple of bytes
		int temp = (448 - ((_byteInput.size() * 8) % 512)); ///< temporary

		pad = static_cast<uint32_t>((temp + 512) % 512); ///< getting no of bits to  be pad
		if (pad == 0)									 ///<  pad is in bits
		{
			pad = 512; ///< at least 1 or max 512 can be added
		}

		sizeMsgBuff = static_cast<uint32_t>((_byteInput.size()) + (pad / 8) + 8);
		sizeMsg = static_cast<unsigned long long>(_byteInput.size()) * 8;
		bMsg = std::vector<unsigned char>(sizeMsgBuff); ///<  no need to pad with 0 coz new bytes
														///<  are already initialize to 0 :)

		///< copying string to buffer
		for (int i = 0; i < _byteInput.size(); i++)
		{
			bMsg[i] = _byteInput[i];
		}

		bMsg[_byteInput.size()] |= 0x80; ///< making first bit of padding 1,

		///< wrting the size value
		for (int i = 8; i > 0; i--)
		{
			bMsg[sizeMsgBuff - i] = static_cast<unsigned char>(sizeMsg >> ((8 - i) * 8) & 0x00000000000000ff);
		}

		return bMsg;
	}

	void Md5::CopyBlock(std::vector<unsigned char> &bMsg, uint32_t block)
	{
		block = block << 6;
		for (uint32_t j = 0; j < 61; j += 4)
		{
			X[j >> 2] = ((static_cast<uint32_t>(bMsg[block + (j + 3)])) << 24) | ((static_cast<uint32_t>(bMsg[block + (j + 2)])) << 16) | ((static_cast<uint32_t>(bMsg[block + (j + 1)])) << 8) | ((static_cast<uint32_t>(bMsg[block + (j)])));
		}
	}

	Md5::Md5()
	{
	}

} ///< namespace Crypto

#endif /* end of include guard :  CRYPTOGRAPHY_MD5_HPP */
