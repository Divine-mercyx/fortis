<?php

class CustomerResource extends JsonResource
{
    public function toArray($request)
    {
        return [
            'id' => $this->id,
            'bvn' => $this->bvn, // @hit
            'nin' => $this->nin, // @hit
            'name' => $this->name,
        ];
    }
}
