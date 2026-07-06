#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

/* Sage AOT Runtime */
typedef struct { int type; union { double number; int boolean; const char* string; void* ptr; } as; } SageValue;
enum { SAGE_NIL=0, SAGE_NUM=1, SAGE_BOOL=2, SAGE_STR=3 };
static SageValue sage_number(double n) { SageValue v; v.type=SAGE_NUM; v.as.number=n; return v; }
static SageValue sage_bool(int b) { SageValue v; v.type=SAGE_BOOL; v.as.boolean=b; return v; }
static SageValue sage_string(const char* s) { SageValue v; v.type=SAGE_STR; v.as.string=s; return v; }
static SageValue sage_nil(void) { SageValue v; v.type=SAGE_NIL; return v; }
static int sage_truthy(SageValue v) { if(v.type==SAGE_NIL) return 0; if(v.type==SAGE_BOOL) return v.as.boolean; if(v.type==SAGE_NUM) return v.as.number!=0.0; return 1; }
static SageValue sage_str(SageValue v);  /* forward decl */
static SageValue sage_strcat(SageValue a, SageValue b);  /* forward decl */
static SageValue sage_add(SageValue a, SageValue b) { if(a.type==SAGE_NUM&&b.type==SAGE_NUM) return sage_number(a.as.number+b.as.number); if(a.type==SAGE_STR&&b.type==SAGE_STR) return sage_strcat(a,b); if(a.type==SAGE_STR||b.type==SAGE_STR){SageValue sa=sage_str(a),sb=sage_str(b);return sage_strcat(sa,sb);} return sage_nil(); }
static SageValue sage_sub(SageValue a, SageValue b) { return sage_number(a.as.number-b.as.number); }
static SageValue sage_mul(SageValue a, SageValue b) { return sage_number(a.as.number*b.as.number); }
static SageValue sage_div(SageValue a, SageValue b) { return sage_number(a.as.number/b.as.number); }
static SageValue sage_mod(SageValue a, SageValue b) { return sage_number(fmod(a.as.number,b.as.number)); }
static SageValue sage_eq(SageValue a, SageValue b) { if(a.type!=b.type) return sage_bool(0); if(a.type==SAGE_NIL) return sage_bool(1); if(a.type==SAGE_BOOL) return sage_bool(a.as.boolean==b.as.boolean); if(a.type==SAGE_NUM) return sage_bool(a.as.number==b.as.number); if(a.type==SAGE_STR) return sage_bool(strcmp(a.as.string,b.as.string)==0); return sage_bool(0); }
static SageValue sage_neq(SageValue a, SageValue b) { return sage_bool(!sage_eq(a,b).as.boolean); }
static SageValue sage_gt(SageValue a, SageValue b) { return sage_bool(a.as.number>b.as.number); }
static SageValue sage_lt(SageValue a, SageValue b) { return sage_bool(a.as.number<b.as.number); }
static SageValue sage_strcat(SageValue a, SageValue b) { if(a.type!=SAGE_STR||b.type!=SAGE_STR) return sage_nil(); size_t la=strlen(a.as.string),lb=strlen(b.as.string); char* r=malloc(la+lb+1); memcpy(r,a.as.string,la); memcpy(r+la,b.as.string,lb); r[la+lb]=0; SageValue v; v.type=SAGE_STR; v.as.string=r; return v; }

enum { SAGE_ARR=4, SAGE_DICT=5, SAGE_TUPLE=6 };
typedef struct { SageValue* elems; int count; int cap; } SageArr;
typedef struct { char** keys; SageValue* vals; int count; int cap; } SageDict;
static SageValue sage_array(int n, ...) { SageArr* a=malloc(sizeof(SageArr)); a->cap=n>4?n:4; a->count=n; a->elems=malloc(sizeof(SageValue)*a->cap); va_list ap; va_start(ap,n); for(int i=0;i<n;i++) a->elems[i]=va_arg(ap,SageValue); va_end(ap); SageValue v; v.type=SAGE_ARR; v.as.ptr=a; return v; }
static int sage_array_len(SageValue v) { if(v.type==SAGE_ARR) return ((SageArr*)v.as.ptr)->count; return 0; }
static SageValue sage_array_get(SageValue v, int i) { if(v.type==SAGE_ARR || v.type==SAGE_TUPLE){SageArr*a=(SageArr*)v.as.ptr; if(i>=0&&i<a->count) return a->elems[i];} return sage_nil(); }
static SageValue sage_index(SageValue c, SageValue i) { if(c.type==SAGE_ARR || c.type==SAGE_TUPLE) return sage_array_get(c,(int)i.as.number); if(c.type==SAGE_DICT){SageDict*d=(SageDict*)c.as.ptr; if(i.type==SAGE_STR) for(int k=0;k<d->count;k++) if(strcmp(d->keys[k],i.as.string)==0) return d->vals[k];} return sage_nil(); }
static SageValue sage_index_set(SageValue c, SageValue i, SageValue val) { if(c.type==SAGE_ARR){SageArr*a=(SageArr*)c.as.ptr; int idx=(int)i.as.number; if(idx>=0&&idx<a->count) a->elems[idx]=val;} if(c.type==SAGE_DICT){SageDict*d=(SageDict*)c.as.ptr; if(i.type==SAGE_STR){for(int k=0;k<d->count;k++) if(strcmp(d->keys[k],i.as.string)==0){d->vals[k]=val;return val;} if(d->count>=d->cap){d->cap=d->cap?d->cap*2:4;d->keys=realloc(d->keys,sizeof(char*)*d->cap);d->vals=realloc(d->vals,sizeof(SageValue)*d->cap);}d->keys[d->count]=strdup(i.as.string);d->vals[d->count]=val;d->count++;}} return val; }
static SageValue sage_dict(int n, ...) { SageDict*d=calloc(1,sizeof(SageDict)); d->cap=n>2?n:2; d->keys=malloc(sizeof(char*)*d->cap); d->vals=malloc(sizeof(SageValue)*d->cap); va_list ap; va_start(ap,n); for(int i=0;i<n;i++){d->keys[i]=strdup(va_arg(ap,const char*));d->vals[i]=va_arg(ap,SageValue);d->count++;} va_end(ap); SageValue v; v.type=SAGE_DICT; v.as.ptr=d; return v; }
static SageValue sage_tuple(int n, ...) { SageArr*a=malloc(sizeof(SageArr)); a->cap=n; a->count=n; a->elems=malloc(sizeof(SageValue)*n); va_list ap; va_start(ap,n); for(int i=0;i<n;i++) a->elems[i]=va_arg(ap,SageValue); va_end(ap); SageValue v; v.type=SAGE_TUPLE; v.as.ptr=a; return v; }
static SageValue sage_slice(SageValue c, SageValue s, SageValue e) { if(c.type!=SAGE_ARR) return sage_nil(); SageArr*a=(SageArr*)c.as.ptr; int si=(int)s.as.number,ei=e.type==SAGE_NIL?a->count:(int)e.as.number; if(si<0)si=0;if(ei>a->count)ei=a->count; int n=ei-si;if(n<0)n=0; return sage_array(0); /* simplified */ }
static void sage_push(SageValue arr, SageValue val) { if(arr.type==SAGE_ARR){SageArr*a=(SageArr*)arr.as.ptr;if(a->count>=a->cap){a->cap=a->cap?a->cap*2:4;a->elems=realloc(a->elems,sizeof(SageValue)*a->cap);}a->elems[a->count++]=val;} }
static SageValue sage_pop(SageValue arr) { if(arr.type==SAGE_ARR){SageArr*a=(SageArr*)arr.as.ptr;if(a->count>0)return a->elems[--a->count];} return sage_nil(); }
static SageValue sage_len(SageValue v) { if(v.type==SAGE_ARR) return sage_number(((SageArr*)v.as.ptr)->count); if(v.type==SAGE_STR) return sage_number(strlen(v.as.string)); if(v.type==SAGE_DICT) return sage_number(((SageDict*)v.as.ptr)->count); return sage_number(0); }
static SageValue sage_range(int n) { SageArr*a=malloc(sizeof(SageArr)); a->cap=n>4?n:4; a->count=n; a->elems=malloc(sizeof(SageValue)*a->cap); for(int i=0;i<n;i++) a->elems[i]=sage_number(i); SageValue v; v.type=SAGE_ARR; v.as.ptr=a; return v; }
static SageValue sage_get_property(SageValue obj, const char* name) { if(obj.type==SAGE_DICT){SageDict*d=(SageDict*)obj.as.ptr; for(int i=0;i<d->count;i++) if(strcmp(d->keys[i],name)==0) return d->vals[i];} return sage_nil(); }
static SageValue sage_dict_keys(SageValue d) { if(d.type!=SAGE_DICT) return sage_array(0); SageDict*dd=(SageDict*)d.as.ptr; SageArr*a=malloc(sizeof(SageArr)); a->cap=dd->count>4?dd->count:4; a->count=dd->count; a->elems=malloc(sizeof(SageValue)*a->cap); for(int i=0;i<dd->count;i++) a->elems[i]=sage_string(dd->keys[i]); SageValue v; v.type=SAGE_ARR; v.as.ptr=a; return v; }
static SageValue sage_str(SageValue v) { char buf[256]; switch(v.type){case SAGE_NUM:{double d=v.as.number;if(d==(double)(long long)d&&d>=-1e15&&d<=1e15)snprintf(buf,sizeof(buf),"%lld",(long long)d);else snprintf(buf,sizeof(buf),"%g",d);break;}case SAGE_STR:return v;case SAGE_BOOL:return sage_string(v.as.boolean?"true":"false");default:return sage_string("nil");}return sage_string(strdup(buf));}
static SageValue sage_tonumber(SageValue v) { if(v.type==SAGE_NUM)return v; if(v.type==SAGE_STR)return sage_number(atof(v.as.string)); return sage_number(0);}
static SageValue sage_type(SageValue v) { switch(v.type){case SAGE_NUM:return sage_string("number");case SAGE_STR:return sage_string("string");case SAGE_BOOL:return sage_string("bool");case SAGE_ARR:return sage_string("array");case SAGE_DICT:return sage_string("dict");default:return sage_string("nil");} }
static void sage_print_value(SageValue v) { switch(v.type) { case SAGE_NUM: { double d=v.as.number; if(d==(double)(long long)d&&d>=-1e15&&d<=1e15) printf("%lld",(long long)d); else printf("%g",d); break; } case SAGE_BOOL: fputs(v.as.boolean?"true":"false",stdout); break; case SAGE_STR: fputs(v.as.string,stdout); break; case SAGE_ARR: { SageArr*a=(SageArr*)v.as.ptr; printf("["); for(int i=0;i<a->count;i++){if(i)printf(", ");sage_print_value(a->elems[i]);} printf("]"); break; } case SAGE_DICT: { SageDict*d=(SageDict*)v.as.ptr; printf("{"); for(int i=0;i<d->count;i++){if(i)printf(", ");printf("\"%s\": ",d->keys[i]);sage_print_value(d->vals[i]);} printf("}"); break; } default: fputs("nil",stdout); } }

static SageValue s_bytes_equal(int argc, SageValue* argv);
static SageValue s_print_hex(int argc, SageValue* argv);

static SageValue s_bytes_equal(int argc, SageValue* argv) {
    SageValue s_a = (argc > 0) ? argv[0] : sage_nil();
    SageValue s_b = (argc > 1) ? argv[1] : sage_nil();
    if (sage_truthy(sage_neq(sage_len(s_a), sage_len(s_b)))) {
        return sage_bool(0);
    }
    { SageValue _iter_t0 = sage_range((int)sage_len(s_a).as.number);
        for (int t0 = 0; t0 < sage_array_len(_iter_t0); t0++) {
            SageValue s_i = sage_array_get(_iter_t0, t0);
            if (sage_truthy(sage_neq(sage_index(s_a, s_i), sage_index(s_b, s_i)))) {
                return sage_bool(0);
            }
        }
    }
    return sage_bool(1);
    return sage_nil();
}

static SageValue s_print_hex(int argc, SageValue* argv) {
    SageValue s_bytes = (argc > 0) ? argv[0] : sage_nil();
    SageValue s_hex_chars = sage_string("0123456789abcdef");
    SageValue s_s = sage_string("");
    { SageValue _iter_t1 = sage_range((int)sage_len(s_bytes).as.number);
        for (int t1 = 0; t1 < sage_array_len(_iter_t1); t1++) {
            SageValue s_i = sage_array_get(_iter_t1, t1);
            (s_s = sage_add(sage_add(s_s, sage_index(s_hex_chars, sage_number((double)((long long)sage_number((double)((unsigned long long)sage_index(s_bytes, s_i).as.number >> (int)sage_number(4).as.number)).as.number & (long long)sage_number(15).as.number)))), sage_index(s_hex_chars, sage_number((double)((long long)sage_index(s_bytes, s_i).as.number & (long long)sage_number(15).as.number)))));
        }
    }
    sage_print_value(s_s); printf("\n");
    return sage_nil();
}

int main(void) {
    /* import sagelink.handshake.noise_ik */
    /* import crypto.aead */
    /* import sys */
    sage_print_value(sage_string("=========================================")); printf("\n");
    sage_print_value(sage_string("Running SageLink Handshake Integration Tests...")); printf("\n");
    sage_print_value(sage_string("=========================================")); printf("\n");
    sage_print_value(sage_string("Generating keypairs...")); printf("\n");
    SageValue s_alice_keys = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "generate_keypair") */;
    SageValue s_bob_keys = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "generate_keypair") */;
    sage_print_value(sage_string("Alice public key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_alice_keys, sage_string("pub")); s_print_hex(1, _args); });
    sage_print_value(sage_string("Bob public key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_bob_keys, sage_string("pub")); s_print_hex(1, _args); });
    sage_print_value(sage_string("Initializing handshake states...")); printf("\n");
    SageValue s_alice_hs = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "initialize_handshake") */;
    SageValue s_bob_hs = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "initialize_handshake") */;
    sage_print_value(sage_string("Writing message 1 (Alice -> Bob)...")); printf("\n");
    SageValue s_payload_1 = sage_string("Hello, Bob! I am Alice.");
    SageValue s_msg1 = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "write_message_1") */;
    sage_print_value(sage_add(sage_string("Message 1 length: "), sage_str(sage_len(s_msg1)))); printf("\n");
    sage_print_value(sage_string("Reading message 1 on Bob's side...")); printf("\n");
    SageValue s_read1 = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "read_message_1") */;
    if (sage_truthy(sage_eq(s_read1, sage_nil()))) {
        sage_print_value(sage_string(" [FAIL] Bob failed to parse message 1")); printf("\n");
        sage_nil() /* unsupported call: sage_get_property(s_sys, "exit") */;
    }
    sage_nil();
    SageValue s_parsed_payload_1 = sage_string("");
    { SageValue _iter_t2 = sage_range((int)sage_len(sage_index(s_read1, sage_string("payload"))).as.number);
        for (int t2 = 0; t2 < sage_array_len(_iter_t2); t2++) {
            SageValue s_i = sage_array_get(_iter_t2, t2);
            (s_parsed_payload_1 = sage_add(s_parsed_payload_1, ({ SageValue _args[1]; _args[0] = sage_index(sage_index(s_read1, sage_string("payload")), s_i); s_chr(1, _args); })));
        }
    }
    sage_print_value(sage_strcat(sage_strcat(sage_string("Bob parsed payload: '"), s_parsed_payload_1), sage_string("'"))); printf("\n");
    if (sage_truthy(sage_eq(s_parsed_payload_1, s_payload_1))) {
        sage_print_value(sage_string(" [PASS] Payload 1 decrypted successfully")); printf("\n");
    } else {
        sage_print_value(sage_string(" [FAIL] Payload 1 mismatch")); printf("\n");
    }
    sage_nil();
    if (sage_truthy(({ SageValue _args[2]; _args[0] = sage_index(s_read1, sage_string("rs")); _args[1] = sage_index(s_alice_keys, sage_string("pub")); s_bytes_equal(2, _args); }))) {
        sage_print_value(sage_string(" [PASS] Bob correctly identified Alice's static public key")); printf("\n");
    } else {
        sage_print_value(sage_string(" [FAIL] Static key mismatch")); printf("\n");
    }
    sage_nil();
    sage_print_value(sage_string("Writing message 2 (Bob -> Alice)...")); printf("\n");
    SageValue s_payload_2 = sage_string("Welcome, Alice! Glad to establish connection.");
    SageValue s_msg2 = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "write_message_2") */;
    sage_print_value(sage_add(sage_string("Message 2 length: "), sage_str(sage_len(s_msg2)))); printf("\n");
    sage_print_value(sage_string("Reading message 2 on Alice's side...")); printf("\n");
    SageValue s_read2 = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "read_message_2") */;
    if (sage_truthy(sage_eq(s_read2, sage_nil()))) {
        sage_print_value(sage_string(" [FAIL] Alice failed to parse message 2")); printf("\n");
        sage_nil() /* unsupported call: sage_get_property(s_sys, "exit") */;
    }
    sage_nil();
    SageValue s_parsed_payload_2 = sage_string("");
    { SageValue _iter_t3 = sage_range((int)sage_len(sage_index(s_read2, sage_string("payload"))).as.number);
        for (int t3 = 0; t3 < sage_array_len(_iter_t3); t3++) {
            SageValue s_i = sage_array_get(_iter_t3, t3);
            (s_parsed_payload_2 = sage_add(s_parsed_payload_2, ({ SageValue _args[1]; _args[0] = sage_index(sage_index(s_read2, sage_string("payload")), s_i); s_chr(1, _args); })));
        }
    }
    sage_print_value(sage_strcat(sage_strcat(sage_string("Alice parsed payload: '"), s_parsed_payload_2), sage_string("'"))); printf("\n");
    if (sage_truthy(sage_eq(s_parsed_payload_2, s_payload_2))) {
        sage_print_value(sage_string(" [PASS] Payload 2 decrypted successfully")); printf("\n");
    } else {
        sage_print_value(sage_string(" [FAIL] Payload 2 mismatch")); printf("\n");
    }
    sage_nil();
    sage_print_value(sage_string("Splitting handshake keys...")); printf("\n");
    SageValue s_alice_transport = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "split_handshake") */;
    SageValue s_bob_transport = sage_nil() /* unsupported call: sage_get_property(s_noise_ik, "split_handshake") */;
    sage_print_value(sage_string("Alice send key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_alice_transport, sage_string("send")); s_print_hex(1, _args); });
    sage_print_value(sage_string("Bob recv key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_bob_transport, sage_string("recv")); s_print_hex(1, _args); });
    sage_print_value(sage_string("Alice recv key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_alice_transport, sage_string("recv")); s_print_hex(1, _args); });
    sage_print_value(sage_string("Bob send key:")); printf("\n");
    ({ SageValue _args[1]; _args[0] = sage_index(s_bob_transport, sage_string("send")); s_print_hex(1, _args); });
    if (sage_truthy(({ SageValue _args[2]; _args[0] = sage_index(s_alice_transport, sage_string("send")); _args[1] = sage_index(s_bob_transport, sage_string("recv")); s_bytes_equal(2, _args); }))) {
        sage_print_value(sage_string(" [PASS] Alice send key matches Bob recv key")); printf("\n");
    } else {
        sage_print_value(sage_string(" [FAIL] Key mismatch (A_send vs B_recv)")); printf("\n");
    }
    sage_nil();
    if (sage_truthy(({ SageValue _args[2]; _args[0] = sage_index(s_alice_transport, sage_string("recv")); _args[1] = sage_index(s_bob_transport, sage_string("send")); s_bytes_equal(2, _args); }))) {
        sage_print_value(sage_string(" [PASS] Alice recv key matches Bob send key")); printf("\n");
    } else {
        sage_print_value(sage_string(" [FAIL] Key mismatch (A_recv vs B_send)")); printf("\n");
    }
    sage_nil();
    sage_print_value(sage_string("Testing post-handshake transport encryption...")); printf("\n");
    SageValue s_pt = sage_string("Top-secret data transmission");
    SageValue s_nonce = sage_array(12, sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(0), sage_number(1));
    SageValue s_aad = sage_array(0);
    SageValue s_enc_out = sage_nil() /* unsupported call: sage_get_property(s_aead, "chacha20_poly1305_encrypt") */;
    SageValue s_dec_pt = sage_nil() /* unsupported call: sage_get_property(s_aead, "chacha20_poly1305_decrypt") */;
    if (sage_truthy(sage_neq(s_dec_pt, sage_nil()))) {
        SageValue s_dec_str = sage_string("");
        { SageValue _iter_t4 = sage_range((int)sage_len(s_dec_pt).as.number);
            for (int t4 = 0; t4 < sage_array_len(_iter_t4); t4++) {
                SageValue s_i = sage_array_get(_iter_t4, t4);
                (s_dec_str = sage_add(s_dec_str, ({ SageValue _args[1]; _args[0] = sage_index(s_dec_pt, s_i); s_chr(1, _args); })));
            }
        }
        if (sage_truthy(sage_eq(s_dec_str, s_pt))) {
            sage_print_value(sage_string(" [PASS] Transport encryption and decryption verified")); printf("\n");
        } else {
            sage_print_value(sage_string(" [FAIL] Transport plaintext mismatch")); printf("\n");
        }
        sage_nil();
    } else {
        sage_print_value(sage_string(" [FAIL] Transport decryption failed")); printf("\n");
    }
    sage_nil();
    sage_print_value(sage_string("=========================================")); printf("\n");
    sage_print_value(sage_string("Handshake tests finished.")); printf("\n");
    sage_print_value(sage_string("=========================================")); printf("\n");
    return 0;
}
