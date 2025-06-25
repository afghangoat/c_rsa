#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

/*
Constraints:
-priv_key.key_size_e must be smaller than N
Please note that in order to work with larger numbers, such as 1024 or 4096 bit keys, not even unsigned long long int will do it.
arbitrary-precision arithmetic common libraries: include <gmp.h> is recommended for this task
*/
int prob_tries=200;
typedef struct RSA_PPK{
    int N;
    int pub_key_exponent;
} RSA_PPK;
void print_pub_key_data(RSA_PPK pub){
    printf("-=Public key data=-\nN=%d\nPublic key exponent e=%d\n---",pub.N,pub.pub_key_exponent);
}
typedef struct RSA_PRIV{
    int q;
    int p;
    int d;
    int N; //not needed to store, but for simplicity
    int key_size_e;
} RSA_PRIV;
void print_priv_key_data(RSA_PRIV priv){
    printf("-=Private key data=-\nFirst prime=%d\nSecond prime=%d\nd secret=%d\nN=%d\nKey size e=%d\n---",priv.q,priv.p,priv.d,priv.N,priv.key_size_e);
}
int pow_mod(int a, int exp, int mod){
    if(mod==1){
        return 0;
    }
    long long x=1, y=a;
    while (exp > 0) {
        if (exp%2 == 1) {
            x = (x*y) % mod;
        }
        y = (y*y) % mod;
        exp /= 2;
    }
    return x % mod;
}

int extended_gcd(int a, int b, int *x, int *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }
    int x1, y1;
    int gcd = extended_gcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return gcd;
}
int mod_inverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1) return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;
    return x1;
}
bool congruent(int a, int b,int m){
    if(a%m==b%m){
        return true;
    }
    return false;
}
int gcd(int a, int b){
    int t=0;
    int ta=a;
    int tb=b;
    while(ta>0){
        t=ta;
        ta=tb%ta;
        tb=t;
    }
    return tb;
}
int fi(int M,bool prime){
    if(prime==true){
        return M-1;
    }
    int amm=0;
    for (int i = 1; i < M; i++)
    {
        int t_gcd=gcd(i,M);
        if(t_gcd==1){
            amm++;
        }
    }
    return amm;
}
bool is_prime_probable(int p, int iters){
    if (p<2){
        return false;
    } 
    if(p==3||p==2){
        return true; //lol
    }
    //int fi_p = fi(p,false);
    //if(fi_p==p-1){
    //    return true;
    //}
    for (int i = 0; i < iters; i++)
    {
        int a=rand()%((int)p-1)+1;//between 1 and p-1
        int t =gcd(a,p);
        if(t!=1){
            return false;
        } else {
            int result=pow_mod(a,p-1,p);
            if(result!=1){
                return false;
            }
            //if a^n-1===1 (m), if not 1:not prime, if 1:goto a
        }
    }
    return true;
}
int get_random_prime(int nmax,int sec_number){
    if(nmax<3){
        return 0;
    }
    int testnum;
    do
    {
        testnum=rand()%nmax;
    } while (is_prime_probable(testnum,prob_tries)!=true&&sec_number!=testnum);
    return testnum;
}
RSA_PRIV generate_rsa_priv_key(int kse){
    RSA_PRIV priv_key;
    priv_key.key_size_e=kse;
    priv_key.q=11;//get_random_prime(block_size/2,0);
    priv_key.p=7;//get_random_prime(block_size/2,priv_key.q);
    priv_key.N=priv_key.p*priv_key.q;
    return priv_key;
}
RSA_PPK generate_rsa_pub_key(RSA_PRIV *priv_key) {
    RSA_PPK pub_key;
    int fi_n = (priv_key->p - 1) * (priv_key->q - 1);
    int public_key_e = priv_key->key_size_e;
    
    priv_key->d = mod_inverse(public_key_e, fi_n);
    if (priv_key->d == 0) {
        printf("Error: No correct modular inverse value exists for d.\n");
        exit(1);
    }
    pub_key.N = priv_key->N;
    pub_key.pub_key_exponent = public_key_e;
    return pub_key;
}
int rsa_encode(int char_msg, RSA_PPK pub_key) {
    int c= pow_mod(char_msg, pub_key.pub_key_exponent, pub_key.N);
    return c;
}

int rsa_decode(int code, RSA_PRIV priv_key) {
    int msg = pow_mod(code, priv_key.d, priv_key.N);
    return msg;
}
//Append this to the beginning of the message for encode.
int rsa_create_OAEP_padding(RSA_PRIV priv_key,int message_length){
	//k-2hlen-2 bytes
	int k = (int)(log2((double)(priv_key.N)));
	int h_len=(int)(log2((double)((double)(k)/2.0-1.0-message_length)));
	int seed=rand()%h_len;
	char mhash[]=" ";
	for(int i=0;i<h_len;i++){
		mhash[i]=(int)((rand()%h_len^seed)%256);
	}
	return mhash;
}
int main(){
	// srand(time(NULL)); //Use this for randomness based on time
    int data = 10;
    printf("Original data: %d\n", data);

    RSA_PRIV priv_key = generate_rsa_priv_key(17); // Public exponent 65537
    RSA_PPK pub_key = generate_rsa_pub_key(&priv_key);
    print_pub_key_data(pub_key);
    print_priv_key_data(priv_key);
    int code= rsa_encode(data, pub_key);
    printf("Encoded: %d\n", code);
    int decoded = rsa_decode(code, priv_key);
    printf("Decoded: %d\n", decoded);
    return 0;
}