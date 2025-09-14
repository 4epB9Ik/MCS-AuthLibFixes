package com.mojang.authlib.yggdrasil;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Iterables;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.mojang.authlib.Environment;
import com.mojang.authlib.GameProfile;
import com.mojang.authlib.HttpAuthenticationService;
import com.mojang.authlib.exceptions.AuthenticationException;
import com.mojang.authlib.exceptions.AuthenticationUnavailableException;
import com.mojang.authlib.minecraft.HttpMinecraftSessionService;
import com.mojang.authlib.minecraft.MinecraftProfileTexture;
import com.mojang.authlib.minecraft.MinecraftProfileTexture.Type;
import com.mojang.authlib.properties.Property;
import com.mojang.authlib.yggdrasil.request.JoinMinecraftServerRequest;
import com.mojang.authlib.yggdrasil.response.HasJoinedMinecraftServerResponse;
import com.mojang.authlib.yggdrasil.response.MinecraftProfilePropertiesResponse;
import com.mojang.authlib.yggdrasil.response.MinecraftTexturesPayload;
import com.mojang.authlib.yggdrasil.response.Response;
import com.mojang.util.UUIDTypeAdapter;
import java.net.InetAddress;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class YggdrasilMinecraftSessionService extends HttpMinecraftSessionService {
    //private static final String[] WHITELISTED_DOMAINS = {".minecraft.net", ".mojang.com"};
    private static final Logger LOGGER = LogManager.getLogger();
    private final URL joinUrl;
    private final URL checkUrl;
    private final URL profileUrl;
    private final PublicKey publicKey;
    private final Gson gson;
    private final LoadingCache<GameProfile, GameProfile> insecureProfiles;
    private static final String defaultUrl = "https://launcher.mcskill.net/";

    protected YggdrasilMinecraftSessionService(YggdrasilAuthenticationService service, Environment env) {
        super(service);
        this.joinUrl = HttpAuthenticationService.constantURL(getBaseUrl() + "sessionserver/session/minecraft/join");
        this.checkUrl = HttpAuthenticationService.constantURL(getBaseUrl() + "sessionserver/session/minecraft/hasJoined");
        this.profileUrl = HttpAuthenticationService.constantURL(getBaseUrl() + "sessionserver/session/minecraft/profile/");
        this.gson = new GsonBuilder().registerTypeAdapter(UUID.class, new UUIDTypeAdapter()).create();
        this.insecureProfiles = CacheBuilder.newBuilder().expireAfterWrite(6L, TimeUnit.HOURS).build(new CacheLoader<GameProfile, GameProfile>() { // from class: com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService.1
            public GameProfile load(GameProfile key) throws Exception {
                return YggdrasilMinecraftSessionService.this.fillGameProfile(key, false);
            }
        });
        LOGGER.info("SkinFix for MCSkill");
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(IOUtils.toByteArray(YggdrasilMinecraftSessionService.class.getResourceAsStream("/yggdrasil_session_pubkey.der")));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new Error("Missing/invalid yggdrasil public key!");
        }
    }

    @Override
    public void joinServer(GameProfile profile, String authenticationToken, String serverId) throws AuthenticationException {
        int attempts = 15;
        JoinMinecraftServerRequest request = new JoinMinecraftServerRequest();
        request.accessToken = authenticationToken;
        request.selectedProfile = profile.getId();
        request.serverId = serverId;
        while (attempts > 0) {
            try {
                getAuthenticationService().makeRequest(this.joinUrl, request, Response.class);
                return;
            } catch (AuthenticationException exception) {
                try {
                    Thread.sleep(1000L);
                    attempts--;
                    System.out.println("Повторяем попытку...");
                    if (attempts == 0) {
                        System.out.println(exception.getLocalizedMessage());
                        throw exception;
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    @Override
    public GameProfile hasJoinedServer(GameProfile user, String serverId, InetAddress address) throws AuthenticationUnavailableException {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("username", user.getName());
        arguments.put("serverId", serverId);
        if (address != null) {
            arguments.put("ip", address.getHostAddress());
        }
        URL url = HttpAuthenticationService.concatenateURL(this.checkUrl, HttpAuthenticationService.buildQuery(arguments));
        try {
            HasJoinedMinecraftServerResponse response = (HasJoinedMinecraftServerResponse) getAuthenticationService().makeRequest(url, null, HasJoinedMinecraftServerResponse.class);
            if (response != null && response.getId() != null) {
                GameProfile result = new GameProfile(response.getId(), user.getName());
                if (response.getProperties() != null) {
                    result.getProperties().putAll(response.getProperties());
                }
                return result;
            }
            return null;
        } catch (AuthenticationUnavailableException var8) {
            throw var8;
        } catch (AuthenticationException e) {
            return null;
        }
    }

    @Override
    public Map<MinecraftProfileTexture.Type, MinecraftProfileTexture> getTextures(GameProfile profile, boolean requireSecure) {
        Property textureProperty = (Property) Iterables.getFirst(profile.getProperties().get("textures"), (Object) null);
        if (textureProperty == null) {
            return new HashMap<Type, MinecraftProfileTexture>();
        }
        try {
            String json = new String(Base64.decodeBase64(textureProperty.getValue()), Charsets.UTF_8);
            MinecraftTexturesPayload result = (MinecraftTexturesPayload) this.gson.fromJson(json, MinecraftTexturesPayload.class);
            if (result != null && result.getTextures() != null) {
                for (Map.Entry<MinecraftProfileTexture.Type, MinecraftProfileTexture> entry : result.getTextures().entrySet()) {
                    if (!isWhitelistedDomain(entry.getValue().getUrl())) {
                        LOGGER.error("Textures payload has been tampered with (non-whitelisted domain)");
                        return new HashMap<Type, MinecraftProfileTexture>();
                    }
                }
                return result.getTextures();
            }
            return new HashMap<Type, MinecraftProfileTexture>();
        } catch (JsonParseException var7) {
            LOGGER.error("Could not decode textures payload", var7);
            return new HashMap<Type, MinecraftProfileTexture>();
        }
    }

    @Override
    public GameProfile fillProfileProperties(GameProfile profile, boolean requireSecure) {
        if (profile.getId() == null) {
            return profile;
        }
        return !requireSecure ? (GameProfile) this.insecureProfiles.getUnchecked(profile) : fillGameProfile(profile, true);
    }

    protected GameProfile fillGameProfile(GameProfile profile, boolean requireSecure) {
        try {
            URL url = HttpAuthenticationService.constantURL(this.profileUrl + UUIDTypeAdapter.fromUUID(profile.getId()));
            MinecraftProfilePropertiesResponse response = (MinecraftProfilePropertiesResponse) getAuthenticationService().makeRequest(url, null, MinecraftProfilePropertiesResponse.class);
            if (response == null) {
                LOGGER.debug("Couldn't fetch profile properties for " + profile + " as the profile does not exist");
                return profile;
            }
            GameProfile result = new GameProfile(response.getId(), response.getName());
            result.getProperties().putAll(response.getProperties());
            profile.getProperties().putAll(response.getProperties());
            LOGGER.debug("Successfully fetched profile properties for " + profile);
            return result;
        } catch (AuthenticationException var6) {
            LOGGER.warn("Couldn't look up profile properties for " + profile, var6);
            return profile;
        }
    }

    @Override
    public YggdrasilAuthenticationService getAuthenticationService() {
        return (YggdrasilAuthenticationService) super.getAuthenticationService();
    }

    private static boolean isWhitelistedDomain(String url) {
        return true;
    }
    private static String getBaseUrl() {
    	
   	 String parsedUrl = System.getProperty("authUrl");
        if (parsedUrl == null || parsedUrl.trim().isEmpty()) {
       	System.out.println("Using defaultUrl: " + defaultUrl);
           return defaultUrl;
        } else {
       	 parsedUrl = parsedUrl.trim();
            if (parsedUrl.endsWith("/")) {
           	 parsedUrl = parsedUrl.substring(0, parsedUrl.length() - 1);
            }
            System.out.println("Using authUrl argument: " + parsedUrl);
            return parsedUrl;
        }
   	
   }
}