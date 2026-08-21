import { HttpClient } from "@angular/common/http";
import { inject, Injectable } from "@angular/core";
import { Observable, tap } from "rxjs";
import { logMessageSize } from "./message-size-logger";

@Injectable({
  providedIn: "root",
})
export class StatusService {
  private http = inject(HttpClient);

  getStatusListByUrl(statusListUrl: string): Observable<string> {
    return this.http.get(statusListUrl, { responseType: 'text' }).pipe(
      tap((statusList) =>
        logMessageSize(
          "Émission",
          "Status-list (réponse, contrôle wallet post-émission)",
          "JWT statuslist+jwt complet",
          statusList,
        ),
      ),
    );
  }
}
