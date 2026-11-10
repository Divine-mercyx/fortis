<?php

class SafeCustomerResource extends JsonResource
{
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'bvn' => Str::mask($this->bvn, '*', 0, 7),
            'has_nin' => filled($this->nin),
        ];
    }
}
