#ifndef CRYPTOGRAPHY_SHA_256_HPP
#define CRYPTOGRAPHY_SHA_256_HPP

#include <array>
#include <cassert>
#include <vector>
#include <string>
#include <exception>

typedef unsigned char byte;


class InvalidOperationException : public std::exception
{
private:
    std::string msg;

public:
    InvalidOperationException(const std::string& message = "") : msg(message)
    {
    }

    const char * what() const noexcept
    {
        return msg.c_str();
    }
};

namespace Crypto
{
    class Sha26
    {
    private:
        /**
         * @brief 
         * 
         * @param x 
         * @param n 
         * @return uint32_t 
         */
        static uint32_t rotl(uint32_t x, byte n);

        /**
         * @brief 
         * 
         * @param x 
         * @param n 
         * @return unsigned int 
         */
        static unsigned int rotr(uint32_t x, byte n);

        /**
         * @brief 
         * 
         * @param x 
         * @param y 
         * @param z 
         * @return uint32_t 
         */
        static uint32_t ch(uint32_t x, uint32_t y, uint32_t z);

        /**
         * @brief 
         * 
         * @param x 
         * @param y 
         * @param z 
         * @return uint32_t 
         */
        static uint32_t maj(uint32_t x, uint32_t y, uint32_t z);

        /**
         * @brief 
         * 
         * @param x 
         * @return uint32_t 
         */
        static uint32_t Sigma0(uint32_t x);

        /**
         * @brief 
         * 
         * @param x 
         * @return uint32_t 
         */
        static uint32_t Sigma1(uint32_t x);

        /**
         * @brief 
         * 
         * @param x 
         * @return uint32_t 
         */
        static uint32_t sigma0(uint32_t x);

        /**
         * @brief 
         * 
         * @param x 
         * @return uint32_t 
         */
        static uint32_t sigma1(uint32_t x);

        /**
         * @brief 
         * 
         * @param m 
         */
        void processBlock(std::array<uint32_t, 16>& m);

    public:
        /**
         * @brief 
         * 
         * 
         * @param data 
         * @param offset 
         * @param len 
         */
        void addData(std::vector<byte> &data, uint32_t offset, uint32_t len);

        /**
         * @brief Get the Hash object
         * 
         * @return std::vector<byte> 
         */
        std::vector<byte> GetHash();
        
        /**
         * @brief Get the Hash U Int 3 2 object
         * 
         * @return std::vector<uint32_t> 
         */
		std::vector<uint32_t> GetHashUInt32();

	private:
        /**
         * @brief 
         * 
         * @param src 
         * @param dest 
         */
		static void toUintArray(std::array<byte, 64>  &src, std::array<uint32_t, 16> &dest);
        
        /**
         * @brief 
         * 
         * @param src 
         * @return std::vector<byte> 
         */
		static std::vector<byte> toByteArray(std::vector<uint32_t> &src);

	public:
        /**
         * @brief 
         * 
         * @param fs 
         * @return std::vector<byte> 
         */
		static std::vector<byte> HashFile(std::fstream& fs);

    private:
        static const std::array<uint32_t, 64> k;
        std::array<uint32_t, 8> h{
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };
        std::array<byte, 64> pending_block;
        uint32_t pending_block_off = 0;
        std::array<uint32_t, 16> uint_buffer;
        // std::vector<uint32_t> uint_buffer = std::vector<uint32_t>(16);
        uint64_t bits_processed = 0;
        bool closed = false;
    };

    ///< Implementation
    const std::array<uint32_t, 64> Sha26::k{
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2

    };

    uint32_t Sha26::rotl(uint32_t x, byte n)
    {
        assert(n < 32);
        return (x << n) | (x >> (32 - n));
    }

    uint32_t Sha26::rotr(uint32_t x, byte n)
    {
        assert(n < 32);
        return (x << n) | (x >> (32 - n));
    }

    uint32_t Sha26::ch(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ ((~x) & z);
    }

    uint32_t Sha26::maj(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    uint32_t Sha26::Sigma0(uint32_t x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    uint32_t Sha26::Sigma1(uint32_t x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    uint32_t Sha26::sigma0(uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    uint32_t Sha26::sigma1(uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }


    void Sha26::processBlock(std::array<uint32_t, 16>& m) 
    {
        assert(m.size() == 16);

		// 1. Prepare the message schedule (W[t]):
		std::vector<uint32_t> v(64);
		for (int t = 0; t < 16; ++t)
		{
			v[t] = m[t];
		}

		for (int t = 16; t < 64; ++t)
		{
			v[t] = sigma1(v[t - 2]) + v[t - 7] + sigma0(v[t - 15]) + v[t - 16];
		}

		
		uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];

		for (int t = 0; t < 64; ++t)
		{
			uint32_t T1 = _h + Sigma1(e) + ch(e, f, g) + k[t] + v[t];
			uint32_t T2 = Sigma0(a) + maj(a, b, c);
			_h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		h[0] = a + h[0];
		h[1] = b + h[1];
		h[2] = c + h[2];
		h[3] = d + h[3];
		h[4] = e + h[4];
		h[5] = f + h[5];
		h[6] = g + h[6];
		h[7] = _h + h[7];

    }

    void Sha26::addData(std::vector<byte> &data, uint32_t offset, uint32_t len) 
    {
        if (closed)
			throw InvalidOperationException("Adding data to a closed hasher.");

		if (len == 0)
			return;

		bits_processed += len * 8;

		while (len > 0)
		{
			uint32_t amount_to_copy;

			if (len < 64)
			{
				if (pending_block_off + len > 64)
					amount_to_copy = 64 - pending_block_off;
				else
					amount_to_copy = len;
			}
			else
				amount_to_copy = 64 - pending_block_off;

			std::copy_n(data.begin() + offset, amount_to_copy, pending_block.begin() + pending_block_off);
			len -= amount_to_copy;
			offset += amount_to_copy;
			pending_block_off += amount_to_copy;

			if (pending_block_off == 64)
			{
				toUintArray(pending_block, uint_buffer);
				processBlock(uint_buffer);
				pending_block_off = 0;
			}
		}


    }
    
    std::vector<byte> Sha26::GetHash() 
    {
        return toByteArray(GetHashUInt32());
    }
    
    std::vector<uint32_t> Sha26::GetHashUInt32() 
    {
        if (!closed)
		{
			uint64_t size_temp = bits_processed;

			addData({0x80}, 0, 1);

			uint32_t available_space = 64 - pending_block_off;

			if (available_space < 8)
			{
				available_space += 64;
			}

			// 0-initialized
			std::vector<unsigned char> padding(available_space);
			// Insert lenght uint64
			for (uint32_t i = 1; i <= 8; ++i)
			{
				padding[padding.size() - i] = static_cast<unsigned char>(size_temp);
				size_temp >>= 8;
			}

			addData(padding, 0u, static_cast<uint32_t>(padding.size()));

			assert(pending_block_off == 0);

			closed = true;
		}

        std::vector h_vEC(std::begin(h), std::end(h));

		return h_vEC;   
    }
    
    void Sha26::toUintArray(std::array<byte, 64> &src, std::array<uint32_t, 16> &dest) 
    {
        for (uint32_t i = 0, j = 0; i < dest.size(); ++i, j += 4)
		{
			dest[i] = (static_cast<uint32_t>(src[j + 0]) << 24) | 
                (static_cast<uint32_t>(src[j + 1]) << 16) | 
                (static_cast<uint32_t>(src[j + 2]) << 8) | 
                (static_cast<uint32_t>(src[j + 3])
            );
		}

    }
    
    std::vector<byte> Sha26::toByteArray(std::vector<uint32_t> &src) 
    {
        std::vector<unsigned char> dest(src.size() * 4);
		int pos = 0;

		for (int i = 0; i < src.size(); ++i)
		{
			dest[pos++] = static_cast<unsigned char>(src[i] >> 24);
			dest[pos++] = static_cast<unsigned char>(src[i] >> 16);
			dest[pos++] = static_cast<unsigned char>(src[i] >> 8);
			dest[pos++] = static_cast<unsigned char>(src[i]);
		}

		return dest;
    }
    
    std::vector<byte> Sha26::HashFile(std::fstream& fs) 
    {
        
    }

} // namespace Crypto

#endif /* end of include guard :  CRYPTOGRAPHY_SHA_256_HPP */
