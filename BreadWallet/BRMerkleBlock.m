//
//  BRMerkleBlock.m
//  BreadWallet
//
//  Created by Aaron Voisine on 10/22/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRMerkleBlock.h"
#import "NSMutableData+Bitcoin.h"
#import "NSData+Bitcoin.h"

#define MAX_TIME_DRIFT    (2*60*60)     // the furthest in the future a block is allowed to be timestamped

#ifdef DVT_TESTNET
#define MAX_PROOF_OF_WORK 0x2000ffffu   // highest value for difficulty target (higher values are less difficult)
#else
#define MAX_PROOF_OF_WORK 0x1e0fffffu   // highest value for difficulty target (higher values are less difficult)
#endif
#define TARGET_TIMESPAN   (14*24*60*60) // the targeted timespan between difficulty target adjustments

// from https://en.bitcoin.it/wiki/Protocol_specification#Merkle_Trees
// Merkle trees are binary trees of hashes. Merkle trees in darkcoin use x11, a combined hash of 11 of the NIST
// SHA-3 finalists. If, when forming a row in the tree (other than the root of the tree), it would have an odd
// number of elements, the final hash is duplicated to ensure that the row has an even number of hashes. First
// form the bottom row of the tree with the ordered x11 hashes of the byte streams of the transactions in the block.
// Then the row above it consists of half that number of hashes. Each entry is the x11 of the 64-byte concatenation
// of the corresponding two hashes below it in the tree. This procedure repeats recursively until we reach a row
// consisting of just a single hash. This is the merkle root of the tree.
//
// from https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#Partial_Merkle_branch_format
// The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
// signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
// are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
// Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
// depth-first traversal is performed, consuming bits and hashes as they written during encoding.
//
// example tree with three transactions, where only tx2 is matched by the bloom filter:
//
//     merkleRoot
//      /     \
//    m1       m2
//   /  \     /  \
// tx1  tx2 tx3  tx3
//
// flag bits (little endian): 00001011 [merkleRoot = 1, m1 = 1, tx1 = 0, tx2 = 1, m2 = 0, byte padding = 000]
// hashes: [tx1, tx2, m2]

#include "NSData+Bitcoin.h"

@interface BRMerkleBlock ()

@property (nonatomic, assign) UInt256 blockHash;
    
@end

@implementation BRMerkleBlock

// message can be either a merkleblock or header message
+ (instancetype)blockWithMessage:(NSData *)message
{
    return [[self alloc] initWithMessage:message];
}

- (instancetype)initWithMessage:(NSData *)message
{
    if (! (self = [self init])) return nil;
    
    if (message.length < 80) return nil;

    NSUInteger off = 0, l = 0, len = 0;
    NSMutableData *d = [NSMutableData data];

    _version = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _prevBlock = [message hashAtOffset:off];
    off += sizeof(UInt256);
    _merkleRoot = [message hashAtOffset:off];
    off += sizeof(UInt256);
    _timestamp = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _target = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _nonce = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    _totalTransactions = [message UInt32AtOffset:off];
    off += sizeof(uint32_t);
    len = (NSUInteger)[message varIntAtOffset:off length:&l]*sizeof(UInt256);
    off += l;
    _hashes = (off + len > message.length) ? nil : [message subdataWithRange:NSMakeRange(off, len)];
    off += len;
    _flags = [message dataAtOffset:off length:&l];
    _height = BLOCK_UNKNOWN_HEIGHT;
    
    [d appendUInt32:_version];
    [d appendBytes:&_prevBlock length:sizeof(_prevBlock)];
    [d appendBytes:&_merkleRoot length:sizeof(_merkleRoot)];
    [d appendUInt32:_timestamp];
    [d appendUInt32:_target];
    [d appendUInt32:_nonce];
    _blockHash = d.SHA256_2;
    return self;
}

- (instancetype)initWithBlockHash:(UInt256)blockHash version:(uint32_t)version prevBlock:(UInt256)prevBlock
merkleRoot:(UInt256)merkleRoot timestamp:(uint32_t)timestamp target:(uint32_t)target nonce:(uint32_t)nonce
totalTransactions:(uint32_t)totalTransactions hashes:(NSData *)hashes flags:(NSData *)flags height:(uint32_t)height
{
    if (! (self = [self init])) return nil;
    
    _blockHash = blockHash;
    _version = version;
    _prevBlock = prevBlock;
    _merkleRoot = merkleRoot;
    _timestamp = timestamp;
    _target = target;
    _nonce = nonce;
    _totalTransactions = totalTransactions;
    _hashes = hashes;
    _flags = flags;
    _height = height;
    
    return self;
}

// true if merkle tree and timestamp are valid, and proof-of-work matches the stated difficulty target
// NOTE: This only checks if the block difficulty matches the difficulty target in the header. It does not check if the
// target is correct for the block's height in the chain. Use verifyDifficultyFromPreviousBlock: for that.
- (BOOL)isValid
{
    // target is in "compact" format, where the most significant byte is the size of resulting value in bytes, the next
    // bit is the sign, and the remaining 23bits is the value after having been right shifted by (size - 3)*8 bits
    static const uint32_t maxsize = MAX_PROOF_OF_WORK >> 24, maxtarget = MAX_PROOF_OF_WORK & 0x00ffffffu;
    const uint32_t size = _target >> 24, target = _target & 0x00ffffffu;
    NSMutableData *d = [NSMutableData data];
    UInt256 merkleRoot, t = UINT256_ZERO;
    int hashIdx = 0, flagIdx = 0;
    NSValue *root =
        [self _walk:&hashIdx :&flagIdx :0 :^id (id hash, BOOL flag) {
            return hash;
        } :^id (id left, id right) {
            UInt256 l, r;

            if (! right) right = left; // if right branch is missing, duplicate left branch
            [left getValue:&l];
            [right getValue:&r];
            d.length = 0;
            [d appendBytes:&l length:sizeof(l)];
            [d appendBytes:&r length:sizeof(r)];
            return uint256_obj(d.SHA256_2);
        }];
    
    [root getValue:&merkleRoot];
    if (_totalTransactions > 0 && ! uint256_eq(merkleRoot, _merkleRoot)) return NO; // merkle root check failed
    
    // check if timestamp is too far in future
    //TODO: use estimated network time instead of system time (avoids timejacking attacks and misconfigured time)
    if (_timestamp > [NSDate timeIntervalSinceReferenceDate] + NSTimeIntervalSince1970 + MAX_TIME_DRIFT) return NO;
    
    // check if proof-of-work target is out of range
    if (target == 0 || target & 0x00800000u || size > maxsize || (size == maxsize && target > maxtarget)) return NO;

    if (size > 3) *(uint32_t *)&t.u8[size - 3] = CFSwapInt32HostToLittle(target);
    else t.u32[0] = CFSwapInt32HostToLittle(target >> (3 - size)*8);
    
    for (int i = sizeof(t)/sizeof(uint32_t) - 1; i >= 0; i--) { // check proof-of-work
        if (CFSwapInt32LittleToHost(_blockHash.u32[i]) < CFSwapInt32LittleToHost(t.u32[i])) break;
        if (CFSwapInt32LittleToHost(_blockHash.u32[i]) > CFSwapInt32LittleToHost(t.u32[i])) return NO;
    }
    
    return YES;
}

- (NSData *)toData
{
    NSMutableData *d = [NSMutableData data];
    
    [d appendUInt32:_version];
    [d appendBytes:&_prevBlock length:sizeof(_prevBlock)];
    [d appendBytes:&_merkleRoot length:sizeof(_merkleRoot)];
    [d appendUInt32:_timestamp];
    [d appendUInt32:_target];
    [d appendUInt32:_nonce];
    
    if (_totalTransactions > 0) {
        [d appendUInt32:_totalTransactions];
        [d appendVarInt:_hashes.length/sizeof(UInt256)];
        [d appendData:_hashes];
        [d appendVarInt:_flags.length];
        [d appendData:_flags];
    }
    
    return d;
}

// true if the given tx hash is included in the block
- (BOOL)containsTxHash:(UInt256)txHash
{
    for (NSUInteger i = 0; i < _hashes.length/sizeof(UInt256); i += sizeof(UInt256)) {
        if (uint256_eq(txHash, [_hashes hashAtOffset:i])) return YES;
    }
    
    return NO;
}

// returns an array of the matched tx hashes
- (NSArray *)txHashes
{
    int hashIdx = 0, flagIdx = 0;
    NSArray *txHashes =
        [self _walk:&hashIdx :&flagIdx :0 :^id (id hash, BOOL flag) {
            return (flag && hash) ? @[hash] : @[];
        } :^id (id left, id right) {
            return [left arrayByAddingObjectsFromArray:right];
        }];
    
    return txHashes;
}

UInt256 setCompact(int32_t nCompact)
{
    int nSize = nCompact >> 24;
    UInt256 nWord = UINT256_ZERO;
    nWord.u32[0] = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord = shiftRight(nWord, 8 * (3 - nSize));
    } else {
        nWord = shiftLeft(nWord, 8 * (nSize - 3));
    }
    return nWord;
}

uint8_t bits(UInt256 number)
{
    for (int pos = 8 - 1; pos >= 0; pos--) {
        if (number.u32[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (number.u32[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

int32_t getCompact(UInt256 number)
{
    int nSize = (bits(number) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = number.u32[0] << 8 * (3 - nSize);
    } else {
        UInt256 bn = shiftRight(number, 8 * (nSize - 3));
        nCompact = bn.u32[0];
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    assert((nCompact & ~0x007fffff) == 0);
    assert(nSize < 256);
    nCompact |= nSize << 24;
    return nCompact;
}

UInt256 add(UInt256 a, UInt256 b) {
    uint64_t carry = 0;
    UInt256 r = UINT256_ZERO;
    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a.u32[i] + (uint64_t)b.u32[i] + carry;
        r.u32[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return r;
}

UInt256 addOne(UInt256 a) {
    UInt256 r = ((UInt256) { .u64 = { 1, 0, 0, 0 } });
    return add(a, r);
}

UInt256 neg(UInt256 a) {
    UInt256 r = UINT256_ZERO;
    for (int i = 0; i < 4; i++) {
        r.u64[i] = ~a.u64[i];
    }
    return r;
}

UInt256 subtract(UInt256 a, UInt256 b) {
    return add(a,addOne(neg(b)));
}

UInt256 shiftLeft(UInt256 a, uint8_t bits) {
    UInt256 r = UINT256_ZERO;
    int k = bits / 64;
    bits = bits % 64;
    for (int i = 0; i < 4; i++) {
        if (i + k + 1 < 4 && bits != 0)
            r.u64[i + k + 1] |= (a.u64[i] >> (64 - bits));
        if (i + k < 4)
            r.u64[i + k] |= (a.u64[i] << bits);
    }
    return r;
}

UInt256 shiftRight(UInt256 a, uint8_t bits) {
    UInt256 r = UINT256_ZERO;
    int k = bits / 64;
    bits = bits % 64;
    for (int i = 0; i < 4; i++) {
        if (i - k - 1 >= 0 && bits != 0)
            r.u64[i - k - 1] |= (a.u64[i] << (64 - bits));
        if (i - k >= 0)
            r.u64[i - k] |= (a.u64[i] >> bits);
    }
    return r;
}

UInt256 divide (UInt256 a,UInt256 b)
{
    UInt256 div = b;     // make a copy, so we can shift.
    UInt256 num = a;     // make a copy, so we can subtract.
    UInt256 r = UINT256_ZERO;                  // the quotient.
    int num_bits = bits(num);
    int div_bits = bits(div);
    assert (div_bits != 0);
    if (div_bits > num_bits) // the result is certainly 0.
        return r;
    int shift = num_bits - div_bits;
    div = shiftLeft(div, shift); // shift so that div and nun align.
    while (shift >= 0) {
        if (uint256_supeq(num,div)) {
            num = subtract(num,div);
            r.u32[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div = shiftRight(div, 1); // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return r;
}

UInt256 divide_by (UInt256 a, uint64_t b)
{
    UInt256 div = ((UInt256) { .u64 = { b, 0, 0, 0 } });   // make a copy, so we can shift.
    UInt256 num = a;     // make a copy, so we can subtract.
    UInt256 r = UINT256_ZERO;                  // the quotient.
    int num_bits = bits(num);
    int div_bits = bits(div);
    assert (div_bits != 0);
    if (div_bits > num_bits) // the result is certainly 0.
        return r;
    int shift = num_bits - div_bits;
    div = shiftLeft(div, shift); // shift so that div and nun align.
    while (shift >= 0) {
        if (uint256_supeq(num,div)) {
            num = subtract(num,div);
            r.u32[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div = shiftRight(div, 1); // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return r;
}

UInt256 multiplyThis32 (UInt256 a,uint32_t b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t n = carry + (uint64_t)b * (uint64_t)a.u32[i];
        a.u32[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return a;
}

-(bool)verifyLWMAFromPreviousBlocks:(NSMutableDictionary *)previousBlocks andTransitionTime:(uint32_t)time {
    UInt256 sum_target = UINT256_ZERO;
    BRMerkleBlock *previousBlock = previousBlocks[uint256_obj(self.prevBlock)];
    
    if (uint256_is_zero(_prevBlock) || previousBlock.height == 0 || previousBlock.height < LWMA_BLOCKS) {
        // This is the first block or the height is < PastBlocksMin
        // Return minimal required work. (1e0ffff0)
        return MAX_PROOF_OF_WORK;
    }

#ifdef DVT_TESTNET
    if (self.timestamp > previousBlock.timestamp + 10*BLOCK_INTERVAL_SECS) {
      return MAX_PROOF_OF_WORK;
    }
#endif
  
    const int64_t T = BLOCK_INTERVAL_SECS; // 2 minute block times
    const int N = LWMA_BLOCKS;
    const int k = (N+1) * T / 2;  // ignore adjust 0.9989^(500/N) from python code
    const int dnorm = 10;

    int t = 0, j = 0;

    // Create Array of the last LWMA_BLOCKS with index starting at 0 for the oldest block
  
    NSMutableArray *sortedBlocks;
    sortedBlocks = [[NSMutableArray alloc] initWithCapacity:LWMA_BLOCKS];

    // First, index backwards since that is what we have
    UInt256 index = self.prevBlock;
    for (int i=0; i < N; i++) {
      BRMerkleBlock *this_block = previousBlocks[uint256_obj(index)];
      [sortedBlocks addObject:this_block];
      index = this_block.prevBlock;
    }
    // one block older than oldest in the array
    previousBlock = previousBlocks[uint256_obj(index)];

    // Now reverse
    sortedBlocks=[[[sortedBlocks reverseObjectEnumerator] allObjects] mutableCopy];

  
    for (int i=0; i < N; i++) {
        BRMerkleBlock *block = sortedBlocks[i];
        if (i > 0) previousBlock = sortedBlocks[i-1];
      
        int64_t currentBlockTime = block.timestamp;
        int64_t previousBlockTime = previousBlock.timestamp;
        int64_t solvetime = currentBlockTime - previousBlockTime;

        if (solvetime > 6*T) solvetime = 6*T;
        j++;

        t += solvetime * j;  // Weighted solvetime sum.

        // Target sum divided by a factor, (k N^2).
        // The factor is a part of the final equation. However we divide sum_target here to avoid
        // potential overflow.
        UInt256 target = setCompact(block.target);
        sum_target = add(sum_target,divide_by(target, (k * N * N)));
    }

    // Keep t reasonable in case strange solvetimes occurred.
    if (t < N * k / dnorm) {
        t = N * k / dnorm;
    }

    UInt256 next_target = multiplyThis32(sum_target, t);
    int32_t compact = getCompact(next_target);
    if (compact > MAX_PROOF_OF_WORK) {
      compact = MAX_PROOF_OF_WORK;
    }

    int32_t diff = self.target - compact;
    return (abs(diff) < 1);
}


// Verifies the block difficulty target is correct for the block's position in the chain. Transition time may be 0 if
// height is not a multiple of BLOCK_DIFFICULTY_INTERVAL.
//
// The difficulty target algorithm works as follows:
// The target must be the same as in the previous block unless the block's height is a multiple of 2016. Every 2016
// blocks there is a difficulty transition where a new difficulty is calculated. The new target is the previous target
// multiplied by the time between the last transition block's timestamp and this one (in seconds), divided by the
// targeted time between transitions (14*24*60*60 seconds). If the new difficulty is more than 4x or less than 1/4 of
// the previous difficulty, the change is limited to either 4x or 1/4. There is also a minimum difficulty value
// intuitively named MAX_PROOF_OF_WORK... since larger values are less difficult.
- (BOOL)verifyDifficultyFromPreviousBlockBitcoin:(BRMerkleBlock *)previous andTransitionTime:(uint32_t)time
{
    if (! uint256_eq(_prevBlock, previous.blockHash) || _height != previous.height + 1) return NO;
    if ((_height % BLOCK_DIFFICULTY_INTERVAL) == 0 && time == 0) return NO;

#if DVT_TESTNET
    //TODO: implement testnet difficulty rule check
    return YES; // don't worry about difficulty on testnet for now
#endif

    if ((_height % BLOCK_DIFFICULTY_INTERVAL) != 0) return (_target == previous.target) ? YES : NO;

    // target is in "compact" format, where the most significant byte is the size of resulting value in bytes, the next
    // bit is the sign, and the remaining 23bits is the value after having been right shifted by (size - 3)*8 bits
    static const uint32_t maxsize = MAX_PROOF_OF_WORK >> 24, maxtarget = MAX_PROOF_OF_WORK & 0x00ffffffu;
    int32_t timespan = (int32_t)((int64_t)previous.timestamp - (int64_t)time), size = previous.target >> 24;
    uint64_t target = previous.target & 0x00ffffffu;

    // limit difficulty transition to -75% or +400%
    if (timespan < TARGET_TIMESPAN/4) timespan = TARGET_TIMESPAN/4;
    if (timespan > TARGET_TIMESPAN*4) timespan = TARGET_TIMESPAN*4;

    // TARGET_TIMESPAN happens to be a multiple of 256, and since timespan is at least TARGET_TIMESPAN/4, we don't lose
    // precision when target is multiplied by timespan and then divided by TARGET_TIMESPAN/256
    target *= timespan;
    target /= TARGET_TIMESPAN >> 8;
    size--; // decrement size since we only divided by TARGET_TIMESPAN/256
    
    while (size < 1 || target > 0x007fffffULL) target >>= 8, size++; // normalize target for "compact" format

    // limit to MAX_PROOF_OF_WORK
    if (size > maxsize || (size == maxsize && target > maxtarget)) target = maxtarget, size = maxsize;

    return (_target == ((uint32_t)target | size << 24)) ? YES : NO;
}

// recursively walks the merkle tree in depth first order, calling leaf(hash, flag) for each stored hash, and
// branch(left, right) with the result from each branch
- (id)_walk:(int *)hashIdx :(int *)flagIdx :(int)depth :(id (^)(id, BOOL))leaf :(id (^)(id, id))branch
{
    if ((*flagIdx)/8 >= _flags.length || (*hashIdx + 1)*sizeof(UInt256) > _hashes.length) return leaf(nil, NO);
    
    BOOL flag = (((const uint8_t *)_flags.bytes)[*flagIdx/8] & (1 << (*flagIdx % 8)));
    
    (*flagIdx)++;
    
    if (! flag || depth == (int)(ceil(log2(_totalTransactions)))) {
        UInt256 hash = [_hashes hashAtOffset:(*hashIdx)*sizeof(UInt256)];
        
        (*hashIdx)++;
        return leaf(uint256_obj(hash), flag);
    }
    
    id left = [self _walk:hashIdx :flagIdx :depth + 1 :leaf :branch];
    id right = [self _walk:hashIdx :flagIdx :depth + 1 :leaf :branch];
    
    return branch(left, right);
}

- (NSUInteger)hash
{
    if (uint256_is_zero(_blockHash)) return super.hash;
    return *(const NSUInteger *)&_blockHash;
}

- (BOOL)isEqual:(id)obj
{
    return self == obj || ([obj isKindOfClass:[BRMerkleBlock class]] && uint256_eq([obj blockHash], _blockHash));
}

@end
