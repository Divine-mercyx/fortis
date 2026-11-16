package ng.paywave.api;

import io.swagger.v3.oas.annotations.media.Schema;

final class TransfersApiResourceSwagger {
    static final class PostTransfersRequest {
        @Schema(example = "1000.50")
        public Double transferAmount;
        @Schema(example = "250")
        public Float fee;
    }
}
