/*
 * GitHub Authentication for SonarQube
 * Copyright (C) 2016-2019 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarsource.auth.github;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.sonar.api.Startable;
import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import com.squareup.okhttp.Credentials;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.ResponseBody;

@ServerSide
public class SecondaryEmailsSupplier implements Startable {
  private static final Logger LOGGER = Loggers.get(SecondaryEmailsSupplier.class);

  private static final String SQ_USER_UPDATE_ENDPOINT = "api/users/update";
  private static final String SQ_USER_UPDATE_FORM_LOGIN = "login";
  private static final String SQ_USER_UPDATE_FORM_SCM_ACCOUNT = "scmAccount";

  private final GitHubSettings gitHubSettings;

  private ExecutorService executorService;
  private final OkHttpClient okHttpClient;

  public SecondaryEmailsSupplier(GitHubSettings gitHubSettings) {
    this.gitHubSettings = gitHubSettings;
    this.okHttpClient = new OkHttpClient();
  }

  @Override
  public void start() {
    executorService = Executors.newSingleThreadExecutor();
    LOGGER.debug("Executor service started");
  }

  @Override
  public void stop() {
    try {
      executorService.shutdown();
      executorService.awaitTermination(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      LOGGER.error("Error during stop", e);
      Thread.currentThread().interrupt();
    }
    LOGGER.debug("Executor service stopped");
  }

  public void update(final String login, final List<String> secondaryEmails) {
    final URL url = getUrl();
    final String credentials = getCredentials();

    if (url == null || credentials == null) {
      return;
    }

    executorService.execute(new Runnable() {

      @Override
      public void run() {
        try {
          executeRequest();
        } catch (IOException e) {
          LOGGER.error("Failed to execute secondary-email-update request", e);
        }
      }

      private void executeRequest() throws IOException {
        FormEncodingBuilder formEncodingBuilder = new FormEncodingBuilder();
        formEncodingBuilder.add(SQ_USER_UPDATE_FORM_LOGIN, login);

        if (secondaryEmails.size() != 0) {
          for (String email : secondaryEmails) {
            formEncodingBuilder.add(SQ_USER_UPDATE_FORM_SCM_ACCOUNT, email);
          }
        } else {
          // add an empty value to submit an empty list which would overwrite
          // what's already stored in SQ
          formEncodingBuilder.add(SQ_USER_UPDATE_FORM_SCM_ACCOUNT, "");
        }

        Request request = new Request.Builder()
            .post(formEncodingBuilder.build())
            .header("Authorization", credentials)
            .url(url)
            .build();

        Response response = okHttpClient.newCall(request).execute();
        try (ResponseBody responseBody = response.body()) {
          if (response.isSuccessful()) {
            LOGGER.info("secondary-email-update request succeeded for login {}", login);
          } else {
            LOGGER.warn("Failed to submit secondary emails to SQ for login {}, code {}", login, response.code());
          }
        }
      }
    });
  }

  private URL getUrl() {
    final String serverAddressBase = gitHubSettings.secondaryEmailsServerAddress();
    if (serverAddressBase == null || serverAddressBase.isEmpty()) {
      LOGGER.error("Failed to get SQ's local server address from configuration");
      return null;
    }

    final URL serverAddress;
    try {
      serverAddress = new URL(serverAddressBase + SQ_USER_UPDATE_ENDPOINT);
    } catch (MalformedURLException e) {
      LOGGER.error("Got malformed SQ's local server address from configuration", e);
      return null;
    }

    return serverAddress;
  }

  private String getCredentials() {
    String token = gitHubSettings.secondaryEmailsToken();
    if (token == null || token.isEmpty()) {
      LOGGER.error("Failed to get token from configuration");
      return null;
    }
    return Credentials.basic(token, "");
  }

}
