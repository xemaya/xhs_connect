package com.xingin.notebase.notedetail.service;

import com.xingin.notebase.entities.followfeed.BaseNoteFollowFeed;
import io.reactivex.Observable;
import java.util.List;

public interface NoteDetailService {
    Observable<List<BaseNoteFollowFeed>> queryNoteDetailFeedData3Up(
            String noteId, int page, boolean hasAdsTag, int num, int fetchMode,
            String source, String sourceScene, String adsTrackId, String adsTrackUrl,
            boolean fromRecLocal, String extraParams);
}
