package com.breadwallet.chendy;

import android.content.Context;
import android.security.keystore.UserNotAuthenticatedException;
import android.text.format.DateUtils;
import android.util.Log;

import com.breadwallet.core.BRCoreKey;
import com.breadwallet.core.BRCoreMasterPubKey;
import com.breadwallet.tools.manager.BRReportsManager;
import com.breadwallet.tools.security.BRKeyStore;
import com.breadwallet.tools.util.BRConstants;
import com.breadwallet.tools.util.Bip39Reader;
import com.breadwallet.tools.util.Utils;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.platform.entities.WalletInfoData;
import com.platform.tools.KVStoreManager;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public class PhraseUtils {

    private static final int PHRASE_LENGTH = 12;//12
    private static final int RANDOM_SEED_LENGTH = 16;//15+5; 12+4
    private static final int PHRASE_WORDS_LIST_LENGTH = 2048;
    /** Joiner for concatenating words with a space inbetween. */
    public static final Joiner SPACE_JOINER = Joiner.on(" ");
    /** Splitter for splitting words on whitespaces. */
    public static final Splitter WHITESPACE_SPLITTER = Splitter.on(Pattern.compile("\\s+"));
    /** Hex encoding used throughout the framework. Use with HEX.encode(byte[]) or HEX.decode(CharSequence). */


    public static synchronized boolean generateRandomSeed(final Context ctx) {
        //if (Utils.isNullOrEmpty(BRKeyStore.getMasterPublicKey(ctx))) {
        SecureRandom sr = new SecureRandom();
        String languageCode = Locale.getDefault().getLanguage();
        Log.d("chendy", "PhraseUtils generateRandomSeed languageCode " + languageCode);//zh
        List<String> wordList = Bip39Reader.getBip39Words(ctx, "zh-Hant");

        final String[] words = wordList.toArray(new String[wordList.size()]);
        if (words.length != PHRASE_WORDS_LIST_LENGTH) {
            BRReportsManager.reportBug(new IllegalArgumentException("the list is wrong, size: " + words.length), true);
            return false;
        }
        final byte[] randomSeed = sr.generateSeed(RANDOM_SEED_LENGTH);
        Log.d("chendy", "randomSeed.length " + randomSeed.length);//zh
        if (randomSeed.length != RANDOM_SEED_LENGTH)
            throw new NullPointerException("failed to create the seed, seed length is not 128: " + randomSeed.length);
        byte[] paperKeyBytes = BRCoreMasterPubKey.generatePaperKey(randomSeed, words);
        if (paperKeyBytes == null || paperKeyBytes.length == 0) {
            Log.d("chendy", "xxxxxxx " +(paperKeyBytes == null));//zh
            BRReportsManager.reportBug(new NullPointerException("failed to encodeSeed"), true);
            return false;
        }
        for (int i = 0; i < paperKeyBytes.length; i++) {//这儿是字节
           // Log.d("chendy", "paperKeyBytes " + paperKeyBytes[i]);//zh
        }
        String[] splitPhrase = new String(paperKeyBytes).split(" ");//这儿就是12个助记词了
        for (int i = 0; i < splitPhrase.length; i++) {//这儿就是12个助记词了
            Log.d("chendy", "splitPhrase " + splitPhrase[i]);//zh
        }
        if (splitPhrase.length != PHRASE_LENGTH) {
            BRReportsManager.reportBug(new NullPointerException("phrase does not have 12 words:" + splitPhrase.length + ", lang: " + languageCode), true);
            return false;
        }

        Log.d("chendy", "Mnemonic " + WHITESPACE_SPLITTER.splitToList(Arrays.toString(splitPhrase)));//zh
        Log.d("chendy", "Mnemonic "+Arrays.toString(splitPhrase).replace(",",""));//zh

        boolean success = false;
        try {
            success = BRKeyStore.putPhrase(paperKeyBytes, ctx, BRConstants.PUT_PHRASE_NEW_WALLET_REQUEST_CODE);
        } catch (UserNotAuthenticatedException e) {
            return false; // While this is wrong (never ignore a UNAE), it seems to not be causing issues at the moment.
        }
        if (!success) return false;
        byte[] phrase;
        try {
            phrase = BRKeyStore.getPhrase(ctx, 0);
        } catch (UserNotAuthenticatedException e) {
            throw new RuntimeException("Failed to retrieve the phrase even though at this point the system auth was asked for sure.");
        }
        if (Utils.isNullOrEmpty(phrase)) throw new NullPointerException("phrase is null!!");
        if (phrase.length == 0) throw new RuntimeException("phrase is empty");
        Log.d("chendy", "助记词转化为seed");
        byte[] seed = BRCoreKey.getSeedFromPhrase(phrase);
        if (seed == null || seed.length == 0) throw new RuntimeException("seed is null");
        byte[] authKey = BRCoreKey.getAuthPrivKeyForAPI(seed);
        if (authKey == null || authKey.length == 0) {
            BRReportsManager.reportBug(new IllegalArgumentException("authKey is invalid"), true);
        }
        BRKeyStore.putAuthKey(authKey, ctx);
        int walletCreationTime = (int) (System.currentTimeMillis() / DateUtils.SECOND_IN_MILLIS);
        BRKeyStore.putWalletCreationTime(walletCreationTime, ctx);
        final WalletInfoData info = new WalletInfoData();
        info.creationDate = walletCreationTime;
        KVStoreManager.putWalletInfo(ctx, info); //push the creation time to the kv store

        //store the serialized in the KeyStore
        byte[] pubKey = new BRCoreMasterPubKey(paperKeyBytes, true).serialize();
        BRKeyStore.putMasterPublicKey(pubKey, ctx);
        // }

        return true;
    }
}
